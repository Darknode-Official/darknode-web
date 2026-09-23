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

  function startTimer() {
    stopTimer();
    timerInterval = setInterval(function() {
      var el = main.querySelector('#sa-timer');
      if (el) {
        el.textContent = formatTime(Date.now() - quizStartTime);
      }
    }, 1000);
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
        activeModule = MODULES.find(function(m) { return m.id === el.dataset.mod; });
        showDifficultyPicker = true;
        selectedDifficulty = 'all';
        render();
      };
    });

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
        '<div style="margin-left:auto;font-family:monospace;font-size:.78rem;color:var(--acc)" id="sa-timer">' + formatTime(Date.now() - quizStartTime) + '</div>' +
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
        if (currentQ >= filteredQuestions.length) {
          stopTimer();
          showResult = true;
          var score = answers.filter(function(a) { return a.correct; }).length;
          var totalTime = Date.now() - quizStartTime;
          scores[mod.id] = { score: score, total: filteredQuestions.length, date: new Date().toISOString(), difficulty: selectedDifficulty, time: totalTime };
          saveScores(scores);
        }
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
    main.querySelector('#sa-home').onclick = function() { activeModule = null; showResult = false; showDifficultyPicker = false; reviewMistakesOnly = false; render(); };
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
