// Social Engineering Simulator — interactive security awareness training
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// ============================================================================
// MANIPULATION TACTICS REFERENCE
// ============================================================================
const TACTICS = [
  { name: 'Urgency', desc: 'Creates time pressure so the target acts without thinking. "Act now or lose access." Bypasses rational decision-making by triggering fight-or-flight response.', examples: ['Your account will be locked in 1 hour', 'Immediate action required', 'Limited time offer expires today'] },
  { name: 'Authority', desc: 'Impersonates someone in power (CEO, IT admin, law enforcement). Humans are hardwired to comply with authority figures, especially in hierarchical organizations.', examples: ['This is the CEO, I need this done now', 'IT department requires your password reset', 'This is the IRS calling about your taxes'] },
  { name: 'Scarcity', desc: 'Makes the opportunity seem rare or limited. Fear of missing out (FOMO) overrides caution. Works especially well combined with urgency.', examples: ['Only 2 spots left', 'First 50 respondents get...', 'This offer won\'t be available again'] },
  { name: 'Social Proof', desc: 'Claims that others have already done the action. Humans look to peers for validation. "Everyone else already updated their password."', examples: ['Your colleagues have already completed this', 'Join 10,000 others who...', '95% of employees have responded'] },
  { name: 'Familiarity/Liking', desc: 'Builds rapport and trust before the ask. People help those they like. Attackers research targets to find common interests, mutual connections, or shared experiences.', examples: ['We met at the conference last week', 'I see we have mutual connections on LinkedIn', 'I\'m a big fan of your work on...'] },
  { name: 'Reciprocity', desc: 'Gives something first to create obligation. When someone does us a favor, we feel compelled to return it. Free gifts, helpful information, or small favors before the big ask.', examples: ['I helped fix your printer, could you...', 'Here\'s a free security tool, just enter your credentials', 'I gave you access to my files, can you share yours?'] },
  { name: 'Fear', desc: 'Threatens negative consequences to force compliance. "Your computer has been compromised" or "Legal action will be taken." Fear bypasses logical thinking.', examples: ['Your computer is infected with a virus', 'Legal proceedings will be initiated', 'Your account has been compromised'] },
  { name: 'Curiosity', desc: 'Uses intrigue to get targets to click or open something. Humans can\'t resist finding out "what happens next." Effective in phishing subject lines and bait scenarios.', examples: ['You won\'t believe what your coworker said about you', 'See who viewed your profile', 'Confidential: salary information attached'] },
];

// ============================================================================
// SCENARIOS — 12 interactive social engineering scenarios
// ============================================================================
const SCENARIOS = [
  {
    id: 'phishing-email',
    name: 'Phishing Email Detection',
    category: 'Phishing',
    difficulty: 'Beginner',
    mitre: 'T1566.001',
    desc: 'Identify which emails are legitimate and which are phishing attempts.',
    tactics: ['Urgency', 'Authority', 'Fear'],
    realWorld: 'Google and Facebook were tricked into paying $123M to a Lithuanian man who sent fake invoices impersonating a hardware supplier (2013-2015).',
    questions: [
      { email: { from: 'security@amaz0n-verify.com', subject: 'Your account has been compromised - Verify Now', body: 'Dear Customer,\n\nWe detected unusual activity on your account. Click the link below to verify your identity within 24 hours or your account will be permanently suspended.\n\nVerify Now: http://amaz0n-verify.com/secure/login\n\nAmazon Security Team' }, isPhishing: true, explanation: 'Fake domain (amaz0n-verify.com not amazon.com). Creates urgency with 24-hour deadline. Generic greeting. Suspicious link domain.' },
      { email: { from: 'noreply@github.com', subject: '[GitHub] A new personal access token was created', body: 'Hey @user,\n\nA fine-grained personal access token (my-ci-token) was recently created on your account.\n\nIf this was you, no further action is needed.\nIf you did not create this token, please review your account security settings immediately.\n\nThanks,\nThe GitHub Team' }, isPhishing: false, explanation: 'Legitimate GitHub notification. Correct sender domain. No urgent link — directs to review settings. Matches GitHub email style.' },
      { email: { from: 'helpdesk@company-it-support.com', subject: 'Password Expiration Notice - Action Required', body: 'Your corporate password will expire in 2 hours.\n\nTo avoid being locked out, please click the link below to reset your password:\n\nhttp://company-it-support.com/reset?user=you@company.com\n\nIT Help Desk' }, isPhishing: true, explanation: 'External domain pretending to be internal IT. 2-hour urgency is unrealistic. Password reset links should come from your actual domain. Your email is in the URL (pre-filled targeting).' },
      { email: { from: 'billing@stripe.com', subject: 'Your invoice from Stripe is ready', body: 'Hi there,\n\nYour latest invoice (#INV-2026-0912) for $49.00 is now available.\n\nYou can view and download it from your Stripe Dashboard.\n\nhttps://dashboard.stripe.com/invoices/INV-2026-0912\n\nThanks,\nStripe' }, isPhishing: false, explanation: 'Legitimate Stripe invoice notification. Correct sender domain. Links to real Stripe dashboard. Professional formatting. No urgency or threats.' },
      { email: { from: 'ceo@c0mpany.com', subject: 'URGENT - Wire Transfer Needed', body: 'Hi,\n\nI need you to process a wire transfer of $45,000 to the following account immediately. This is for a confidential acquisition — do not discuss with anyone.\n\nBank: First National\nAccount: 1234567890\nRouting: 021000021\n\nPlease confirm when done.\n\nSent from my iPhone' }, isPhishing: true, explanation: 'Classic BEC (Business Email Compromise). Spoofed CEO domain (c0mpany with zero). Urgency + authority + secrecy. "Sent from my iPhone" is a common trick to excuse informal tone.' },
    ]
  },
  {
    id: 'vishing',
    name: 'Voice Phishing (Vishing)',
    category: 'Vishing',
    difficulty: 'Intermediate',
    mitre: 'T1566.004',
    desc: 'Identify manipulation tactics in a phone call transcript.',
    tactics: ['Authority', 'Urgency', 'Fear'],
    realWorld: 'In 2020, Twitter was breached when attackers called employees pretending to be IT support, obtaining VPN credentials that led to the compromise of high-profile accounts.',
    questions: [
      { scenario: 'You receive a call:\n\nCaller: "Hi, this is Mike from the IT Security department. We\'ve detected a security breach affecting your workstation. I need your employee ID and current password to run a diagnostic scan immediately. If we don\'t act now, the malware could spread to the entire network."', isLegit: false, redFlags: ['IT would never ask for your password over the phone', 'Creating urgency with "spread to entire network"', 'No way to verify caller identity', 'Legitimate IT can reset access without your password'], correctAction: 'Hang up. Call IT directly using the number from your company directory (not a number the caller provides). Report the call to security.' },
      { scenario: 'You receive a call:\n\nCaller: "Hello, this is Sarah from your bank\'s fraud department. We noticed a suspicious $2,400 charge on your credit card ending in 4823. To verify this wasn\'t you, I need your full card number, the CVV on the back, and your online banking password so I can freeze the account."', isLegit: false, redFlags: ['Banks never ask for full card numbers — they already have it', 'Never give CVV over the phone', 'Banks never ask for your online banking password', 'They gave the last 4 digits to sound legitimate (partial information pretext)'], correctAction: 'Hang up. Call the number on the back of your card directly. Never give card details or passwords to incoming callers.' },
    ]
  },
  {
    id: 'pretexting',
    name: 'Pretexting (IT Impersonation)',
    category: 'Pretexting',
    difficulty: 'Intermediate',
    mitre: 'T1598',
    desc: 'Recognize when someone is using a false pretext to extract information.',
    tactics: ['Authority', 'Familiarity/Liking'],
    realWorld: 'Hewlett Packard hired private investigators who used pretexting to obtain phone records of journalists and board members by impersonating them to telephone companies (2006).',
    questions: [
      { scenario: 'You get a Teams message from "IT Support" (new account you haven\'t seen before):\n\n"Hi! We\'re migrating all accounts to the new Microsoft 365 tenant this afternoon. I need you to go to portal-365-migration.com and log in with your current credentials so we can transfer your data. This needs to be done by 3 PM or you\'ll lose access to your email and files."', isLegit: false, redFlags: ['Unknown/new account claiming to be IT', 'External URL not on company domain', 'Asking for credentials on third-party site', 'Tight deadline creating urgency', 'Threat of losing access (fear tactic)'], correctAction: 'Do not click the link. Verify with your real IT department through a known channel. Report the message as suspicious.' },
    ]
  },
  {
    id: 'baiting',
    name: 'Baiting (USB Drop)',
    category: 'Baiting',
    difficulty: 'Beginner',
    mitre: 'T1091',
    desc: 'A USB drive was found in the company parking lot labeled "Q4 Salary Increases - Confidential". What do you do?',
    tactics: ['Curiosity'],
    realWorld: 'In a 2016 study, researchers dropped 297 USB drives around a university campus. 48% were plugged in, and files were opened on 290 (98%) of the connected drives.',
    questions: [
      { scenario: 'You find a USB drive in the parking lot labeled "Q4 2026 Salary Increases - CONFIDENTIAL - HR ONLY". What should you do?', options: [
        { text: 'Plug it into your work computer to see if you can identify the owner', correct: false, feedback: 'WRONG. This is exactly what the attacker wants. USB drives can contain auto-executing malware (BadUSB, Rubber Ducky), ransomware, or data-stealing payloads. Plugging it in could compromise your entire workstation and potentially the network.' },
        { text: 'Plug it into a personal device since it won\'t affect work systems', correct: false, feedback: 'WRONG. Your personal device can still be compromised. Malware can steal personal data, banking credentials, or use your device to pivot into corporate VPN connections.' },
        { text: 'Turn it in to IT/Security without plugging it in anywhere', correct: true, feedback: 'CORRECT. IT security can analyze the drive safely in an isolated environment. Never plug unknown USB devices into any computer. The label "Salary Increases" is designed to exploit curiosity — a classic baiting tactic.' },
        { text: 'Throw it away — it\'s probably just a lost drive', correct: false, feedback: 'PARTIALLY CORRECT in that you shouldn\'t plug it in, but throwing it away misses the opportunity to alert security about a potential attack. If an attacker dropped multiple drives, other employees might find them too.' },
      ] },
    ]
  },
  {
    id: 'tailgating',
    name: 'Tailgating / Piggybacking',
    category: 'Physical',
    difficulty: 'Beginner',
    mitre: 'T1200',
    desc: 'Someone is trying to follow you through a badge-access door.',
    tactics: ['Social Proof', 'Familiarity/Liking'],
    realWorld: 'Social engineers routinely gain physical access to secure facilities by carrying boxes (hands too full to badge), wearing uniforms (delivery, maintenance), or simply waiting for someone to hold the door.',
    questions: [
      { scenario: 'You badge into the server room. A person in business attire carrying a laptop bag is right behind you and says: "Hey, can you hold the door? I left my badge at my desk — I\'m just here for a quick meeting with the network team." They seem friendly and in a hurry. What do you do?', options: [
        { text: 'Hold the door — they look like they belong here', correct: false, feedback: 'WRONG. Appearance means nothing. Social engineers dress appropriately for their target environment. Holding the door bypasses physical access controls entirely.' },
        { text: 'Ask them to wait while you call the network team to verify', correct: false, feedback: 'CLOSE, but the person could give a fake name. Better to direct them to reception or security.' },
        { text: 'Politely decline and direct them to reception/security to get a temporary badge', correct: true, feedback: 'CORRECT. "I\'m sorry, I can\'t let anyone in without a badge — company policy. Reception can issue you a temporary one." This is firm but professional. Every employee is responsible for physical security.' },
        { text: 'Let them in but report it to security afterward', correct: false, feedback: 'WRONG. The damage is done once they\'re inside. Reporting afterward doesn\'t undo unauthorized access to the server room. Always prevent, don\'t just report.' },
      ] },
    ]
  },
  {
    id: 'bec',
    name: 'Business Email Compromise',
    category: 'BEC',
    difficulty: 'Advanced',
    mitre: 'T1534',
    desc: 'The CEO urgently needs a wire transfer processed.',
    tactics: ['Authority', 'Urgency', 'Fear'],
    realWorld: 'The FBI reports BEC losses exceeded $2.7 billion in 2022 alone. Ubiquiti Networks lost $46.7 million to a BEC scam in 2015.',
    questions: [
      { scenario: 'You receive this email:\n\nFrom: CEO John Smith <j.smith@company-corp.com> (your company is company.com)\nSubject: Urgent and Confidential\n\n"I\'m in a meeting with our lawyers and we need to process an emergency payment of $89,000 for a confidential acquisition. This cannot wait and must not be discussed with anyone else. Please wire to:\n\nBank: Wells Fargo\nAccount: 9876543210\nBeneficiary: Global Ventures LLC\n\nConfirm when done. I\'ll explain everything after the meeting.\n\nSent from my iPhone"', options: [
        { text: 'Process the transfer — the CEO asked and it\'s urgent', correct: false, feedback: 'WRONG. This is a textbook BEC attack. The domain is wrong (company-corp.com vs company.com), the request demands secrecy, and it bypasses normal approval processes.' },
        { text: 'Reply to the email asking for more details', correct: false, feedback: 'WRONG. You\'d be replying to the attacker, who will provide convincing details. Never verify through the same channel that delivered the request.' },
        { text: 'Call the CEO directly on their known phone number to verify', correct: true, feedback: 'CORRECT. Always verify large financial requests through a different communication channel. Call the CEO\'s known number, walk to their office, or check with their assistant. The "confidential" framing is designed to prevent you from doing exactly this.' },
        { text: 'Forward it to IT and wait', correct: false, feedback: 'PARTIALLY CORRECT — reporting to IT is good, but you should also actively verify with the CEO since delay could matter if it were legitimate. A combined approach: call the CEO AND report to security.' },
      ] },
    ]
  },
  {
    id: 'smishing',
    name: 'SMS Phishing (Smishing)',
    category: 'Smishing',
    difficulty: 'Beginner',
    mitre: 'T1566',
    desc: 'Analyze a suspicious text message about a package delivery.',
    tactics: ['Urgency', 'Curiosity'],
    realWorld: 'Flubot malware spread via SMS messages claiming to be package delivery notifications, infecting millions of Android devices across Europe in 2021.',
    questions: [
      { scenario: 'You receive this text message:\n\n"USPS: Your package #US9514961195221 could not be delivered. Schedule redelivery: http://usps-redelivery.info/track?id=US9514961195221"\n\nYou are expecting a package. What do you do?', options: [
        { text: 'Click the link — I am expecting a package', correct: false, feedback: 'WRONG. The domain usps-redelivery.info is NOT usps.com. Attackers register look-alike domains. The link likely leads to a credential phishing page or malware download.' },
        { text: 'Go directly to usps.com and track using the tracking number', correct: true, feedback: 'CORRECT. Never click links in SMS messages. Go directly to the official website (usps.com) by typing it in your browser. If the tracking number is legitimate, it will show up there.' },
        { text: 'Reply STOP to unsubscribe', correct: false, feedback: 'WRONG. Replying confirms your phone number is active, which leads to more spam/phishing messages. Never reply to suspicious texts.' },
        { text: 'Call the number back to verify', correct: false, feedback: 'RISKY. Smishing messages may use spoofed numbers or premium-rate numbers. Call USPS at their official number from usps.com instead.' },
      ] },
    ]
  },
  {
    id: 'qrcode',
    name: 'QR Code Attack (Quishing)',
    category: 'Quishing',
    difficulty: 'Intermediate',
    mitre: 'T1566',
    desc: 'A QR code is posted offering "free WiFi" at a coffee shop.',
    tactics: ['Reciprocity', 'Curiosity'],
    realWorld: 'In 2022, attackers placed fake QR codes on parking meters in Austin, Texas, directing victims to a phishing site that stole payment card information.',
    questions: [
      { scenario: 'At a coffee shop, you see a printed sign:\n\n"FREE HIGH-SPEED WiFi\nScan QR Code to Connect\n[QR CODE]\nNo password needed!"\n\nThe sign looks professionally printed and matches the shop\'s branding. What\'s the risk?', options: [
        { text: 'It\'s fine — the coffee shop probably set it up', correct: false, feedback: 'WRONG. Anyone can print and place a QR code. The QR could redirect to: (1) a rogue WiFi captive portal stealing credentials, (2) a malware download, (3) a phishing page mimicking a login. You can\'t verify where a QR code points just by looking at it.' },
        { text: 'Scan it but check the URL before proceeding', correct: false, feedback: 'PARTIALLY CORRECT. Checking the URL is better than blindly proceeding, but sophisticated attacks use convincing domains. Also, some QR scanners auto-open URLs.' },
        { text: 'Ask a staff member for the WiFi name and password directly', correct: true, feedback: 'CORRECT. Verify WiFi details with staff directly. Configure your WiFi settings manually. QR codes can be placed by anyone — even if the sign looks official, it could be a sticker placed over the real one.' },
        { text: 'Use my mobile data instead', correct: false, feedback: 'SAFE but not always practical. The best approach is to verify with staff and connect manually. Using your own data is a good backup when public WiFi seems suspicious.' },
      ] },
    ]
  },
  {
    id: 'deepfake',
    name: 'Deepfake Video Call',
    category: 'Deepfake',
    difficulty: 'Advanced',
    mitre: 'T1598',
    desc: 'Your CEO appears on a video call requesting an urgent transfer.',
    tactics: ['Authority', 'Urgency', 'Fear'],
    realWorld: 'In 2024, a Hong Kong finance worker was tricked into transferring $25 million after a video conference with deepfake recreations of the company CFO and other colleagues.',
    questions: [
      { scenario: 'You receive a video call on Zoom. It appears to be your CFO and two other executives you recognize. The CFO says:\n\n"We need to process a $4.2 million transfer to finalize the acquisition we discussed last week. This is time-sensitive — the deal closes in 2 hours. I\'m sending you the wire details now via chat. Please process this immediately and keep it confidential until the announcement."\n\nThe video quality is slightly lower than usual but the faces and voices seem right. What do you do?', options: [
        { text: 'Process the transfer — I can see the CFO on video', correct: false, feedback: 'WRONG. Deepfake technology can now create convincing real-time video of anyone using just a few photos and voice samples. The $25M Hong Kong incident proved this exact scenario.' },
        { text: 'Ask the CFO a personal question only they would know', correct: false, feedback: 'RISKY. Deepfake operators often research their targets extensively. They may know personal details from social media. Also, AI can generate plausible responses.' },
        { text: 'Hang up. Call the CFO directly on their known number. Follow normal financial approval procedures.', correct: true, feedback: 'CORRECT. No amount of video/voice verification is reliable anymore. Deepfakes are now indistinguishable in real-time calls. Always: (1) Verify via a separate channel, (2) Follow established financial procedures, (3) Any request to bypass procedures is a red flag.' },
        { text: 'Ask IT to verify the call is legitimate', correct: false, feedback: 'PARTIALLY CORRECT — good instinct to verify, but IT cannot verify a deepfake in real-time. The immediate action is to disengage and verify through a completely separate channel.' },
      ] },
    ]
  },
  {
    id: 'linkedin-recon',
    name: 'LinkedIn Reconnaissance',
    category: 'OSINT',
    difficulty: 'Intermediate',
    mitre: 'T1593.001',
    desc: 'A recruiter is gathering intelligence through LinkedIn.',
    tactics: ['Familiarity/Liking', 'Reciprocity'],
    realWorld: 'North Korean hackers created fake LinkedIn profiles posing as recruiters from major tech companies, targeting security researchers and engineers with malware disguised as job assessments.',
    questions: [
      { scenario: 'You receive a LinkedIn message:\n\n"Hi! I\'m a senior recruiter at [Major Tech Company]. I came across your profile and I\'m very impressed with your experience at [Your Company]. We have an exciting role that matches your skills perfectly.\n\nBefore we schedule a call, could you share:\n1. What security tools does your team currently use?\n2. How large is your security team?\n3. What cloud provider do you use?\n4. Are you using any specific SIEM or EDR?\n\nThis helps me match you with the right team. The role pays $250-350K + equity.\n\nLooking forward to connecting!"', options: [
        { text: 'Share the information — it seems like a legitimate recruiter', correct: false, feedback: 'WRONG. These questions are intelligence gathering, not recruitment. A legitimate recruiter asks about YOUR skills, not your company\'s security infrastructure. This is classic OSINT reconnaissance that could be used to plan an attack.' },
        { text: 'Reply with general answers without specifics', correct: false, feedback: 'RISKY. Even general information helps attackers. "We use CrowdStrike" tells them what EDR to build evasion for. Any information about your security stack is valuable to an attacker.' },
        { text: 'Decline the questions, verify the recruiter\'s identity independently, and report to security', correct: true, feedback: 'CORRECT. Verify the recruiter exists at the claimed company via the company\'s official website (not LinkedIn). Never share details about your security tools, team size, or infrastructure. Report the interaction to your security team.' },
        { text: 'Accept but only share publicly available information', correct: false, feedback: 'WRONG. Engaging at all validates your profile as a target. The questions themselves are red flags — no legitimate recruiter needs to know your SIEM or EDR vendor.' },
      ] },
    ]
  },
  {
    id: 'supply-chain-se',
    name: 'Supply Chain Social Engineering',
    category: 'Supply Chain',
    difficulty: 'Advanced',
    mitre: 'T1199',
    desc: 'A vendor requests updated credentials for "system migration".',
    tactics: ['Authority', 'Urgency', 'Familiarity/Liking'],
    realWorld: 'The Target data breach (2013, 40M credit cards) began when attackers compromised an HVAC vendor\'s credentials to access Target\'s network.',
    questions: [
      { scenario: 'You receive an email from your known SaaS vendor contact (correct name, correct email domain):\n\n"Hi,\n\nWe\'re migrating our infrastructure this weekend. To ensure uninterrupted service, we need you to update the API credentials on your end. Please provide your current API key and admin portal password so we can test the connection from our new servers.\n\nThis must be done before Friday 5 PM or your service will be interrupted.\n\nThanks,\nMike (your usual contact)"\n\nYou recognize the name and the email domain is correct.', options: [
        { text: 'Send the credentials — it\'s from a known contact', correct: false, feedback: 'WRONG. Even legitimate vendor contacts can be compromised. Their email account may be hacked, or the email may be spoofed. Vendors should never need YOUR admin password for THEIR infrastructure migration.' },
        { text: 'Call Mike at his known phone number to verify the request', correct: true, feedback: 'CORRECT. Always verify credential requests through a different channel, even from known contacts. If Mike confirms, establish a secure method to share credentials (never via email). If he doesn\'t know about it, his email may be compromised.' },
        { text: 'Reply asking for more details about the migration', correct: false, feedback: 'WRONG. If the account is compromised, the attacker will provide convincing details. Replying to a potentially compromised email channel does not verify anything.' },
        { text: 'Ignore it — if it\'s real they\'ll follow up', correct: false, feedback: 'RISKY. If legitimate, ignoring could cause service disruption. The responsible action is to actively verify through a separate channel, not to ignore.' },
      ] },
    ]
  },
  {
    id: 'watering-hole',
    name: 'Watering Hole Attack',
    category: 'Web',
    difficulty: 'Advanced',
    mitre: 'T1189',
    desc: 'Your favorite tech blog has been compromised.',
    tactics: ['Familiarity/Liking', 'Curiosity'],
    realWorld: 'In 2013, attackers compromised the iOS developer forum (iPhoneDevSDK.com) to target Apple employees, infecting their Macs with malware. Forbes.com was also compromised to target defense and financial sector visitors.',
    questions: [
      { scenario: 'You visit a tech blog you read daily. Today:\n- The site loads slower than usual\n- Your browser briefly shows "Connecting to cdn-analytics-update.com" in the status bar\n- An article asks you to "update your Flash Player" to view embedded content\n- Your antivirus pops up a brief warning but then clears\n\nWhat should you do?', options: [
        { text: 'Update Flash Player as suggested — it\'s probably just outdated', correct: false, feedback: 'WRONG. Flash Player has been discontinued since 2020. Any site asking you to install Flash is either compromised or malicious. This is a classic drive-by download attack.' },
        { text: 'Ignore the warnings and continue reading — it\'s a trusted site', correct: false, feedback: 'WRONG. Trusted sites can be compromised. The slow load, external domain connection, fake Flash update, and AV alert are all indicators of a watering hole attack.' },
        { text: 'Close the browser immediately, run a full AV scan, report to IT, avoid the site until verified', correct: true, feedback: 'CORRECT. Multiple red flags: (1) External domain not associated with the site, (2) Fake Flash update (Flash is dead), (3) AV alert. Close the browser, scan your system, clear browser cache, and report to security. The site may be serving exploit kits to visitors.' },
        { text: 'Clear cookies and reload the page', correct: false, feedback: 'WRONG. Reloading exposes you again. If the site is serving an exploit kit, each visit is another chance for infection. Close and don\'t return until the site is confirmed clean.' },
      ] },
    ]
  },
];

// ============================================================================
// RENDER
// ============================================================================
export function renderSocialEngSim(main) {
  var activeTab = 'scenarios';
  var scores = {};
  try { scores = JSON.parse(localStorage.getItem('se_sim_scores') || '{}'); } catch (_) {}

  function saveScores() { try { localStorage.setItem('se_sim_scores', JSON.stringify(scores)); } catch (_) {} }

  function render() {
    main.innerHTML =
      '<h1 class="pg-h1">Social Engineering Simulator</h1>' +
      '<p class="muted pg-sub">Interactive security awareness training. Test your ability to recognize manipulation tactics.</p>' +
      '<div class="tab-bar" style="overflow-x:auto;flex-wrap:nowrap">' +
        '<button class="tab' + (activeTab === 'scenarios' ? ' active' : '') + '" data-tab="scenarios">Scenarios</button>' +
        '<button class="tab' + (activeTab === 'tactics' ? ' active' : '') + '" data-tab="tactics">Manipulation Tactics</button>' +
        '<button class="tab' + (activeTab === 'scores' ? ' active' : '') + '" data-tab="scores">Your Scores</button>' +
        '<button class="tab' + (activeTab === 'policy' ? ' active' : '') + '" data-tab="policy">Policy Generator</button>' +
      '</div>' +
      '<div id="se-content" style="margin-top:12px"></div>';

    main.querySelector('.tab-bar').onclick = function(e) {
      var b = e.target.closest('.tab');
      if (!b) return;
      activeTab = b.dataset.tab;
      render();
    };

    var content = main.querySelector('#se-content');
    if (activeTab === 'scenarios') renderScenariosTab(content);
    else if (activeTab === 'tactics') renderTacticsTab(content);
    else if (activeTab === 'scores') renderScoresTab(content);
    else if (activeTab === 'policy') renderPolicyTab(content);
  }

  function renderScenariosTab(container) {
    container.innerHTML =
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px">' +
      SCENARIOS.map(function(s) {
        var score = scores[s.id];
        var diffColor = s.difficulty === 'Beginner' ? '#00e676' : s.difficulty === 'Intermediate' ? '#ffd600' : '#ff9100';
        return '<div class="arse-card" style="cursor:pointer" data-scenario="' + s.id + '">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
            '<span style="font-weight:700;font-size:.88rem">' + esc(s.name) + '</span>' +
            '<span style="font-size:.6rem;color:' + diffColor + ';border:1px solid ' + diffColor + ';padding:1px 5px;border-radius:3px">' + esc(s.difficulty) + '</span>' +
          '</div>' +
          '<div style="font-size:.72rem;color:var(--acc);margin-bottom:4px">' + esc(s.category) + ' | ' + esc(s.mitre) + '</div>' +
          '<div style="font-size:.78rem;color:var(--mut);margin-bottom:6px">' + esc(s.desc) + '</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">Tactics: ' + s.tactics.join(', ') + '</div>' +
          (score !== undefined ? '<div style="margin-top:6px;font-size:.75rem;font-weight:600;color:' + (score >= 80 ? '#00e676' : score >= 50 ? '#ffd600' : '#ff1744') + '">Best score: ' + score + '%</div>' : '<div style="margin-top:6px;font-size:.72rem;color:var(--mut)">Not attempted</div>') +
        '</div>';
      }).join('') +
      '</div>';

    container.onclick = function(e) {
      var card = e.target.closest('[data-scenario]');
      if (!card) return;
      var scenarioId = card.dataset.scenario;
      var scenario = SCENARIOS.find(function(s) { return s.id === scenarioId; });
      if (scenario) runScenario(container, scenario);
    };
  }

  function runScenario(container, scenario) {
    var qIdx = 0;
    var correct = 0;
    var total = scenario.questions.length;

    function showQuestion() {
      var q = scenario.questions[qIdx];
      var html = '<div style="max-width:700px">' +
        '<button class="btn sm ghost" id="se-back" style="margin-bottom:12px">Back to scenarios</button>' +
        '<h2 class="pg-h2">' + esc(scenario.name) + '</h2>' +
        '<p style="font-size:.78rem;color:var(--mut);margin-bottom:12px">Question ' + (qIdx + 1) + ' of ' + total + '</p>';

      if (q.email) {
        html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:12px;font-size:.82rem">' +
          '<div style="margin-bottom:4px"><strong>From:</strong> ' + esc(q.email.from) + '</div>' +
          '<div style="margin-bottom:8px"><strong>Subject:</strong> ' + esc(q.email.subject) + '</div>' +
          '<div style="white-space:pre-wrap;color:var(--mut);line-height:1.6">' + esc(q.email.body) + '</div>' +
        '</div>' +
        '<p style="font-size:.85rem;font-weight:600;margin-bottom:8px">Is this email phishing or legitimate?</p>' +
        '<div style="display:flex;gap:8px" id="se-answers">' +
          '<button class="btn sm" data-answer="phishing" style="min-width:120px">Phishing</button>' +
          '<button class="btn sm ghost" data-answer="legit" style="min-width:120px">Legitimate</button>' +
        '</div>';
      } else if (q.scenario) {
        html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:12px;font-size:.82rem;white-space:pre-wrap;line-height:1.6">' + esc(q.scenario) + '</div>';
        if (q.options) {
          html += '<div id="se-answers" style="display:flex;flex-direction:column;gap:6px">' +
            q.options.map(function(o, i) {
              return '<button class="btn sm ghost" data-answer="' + i + '" style="text-align:left;white-space:normal;padding:10px 14px">' + esc(o.text) + '</button>';
            }).join('') +
          '</div>';
        } else {
          html += '<p style="font-size:.85rem;font-weight:600;margin-bottom:8px">Is this legitimate?</p>' +
          '<div style="display:flex;gap:8px" id="se-answers">' +
            '<button class="btn sm" data-answer="legit">Legitimate</button>' +
            '<button class="btn sm ghost" data-answer="suspicious">Suspicious</button>' +
          '</div>';
        }
      }
      html += '<div id="se-feedback" style="margin-top:12px"></div></div>';
      container.innerHTML = html;

      container.querySelector('#se-back').onclick = function() { renderScenariosTab(container); };

      container.querySelector('#se-answers').onclick = function(ev) {
        var btn = ev.target.closest('[data-answer]');
        if (!btn) return;
        var answer = btn.dataset.answer;
        var isCorrect = false;
        var feedback = '';

        if (q.email) {
          isCorrect = (answer === 'phishing') === q.isPhishing;
          feedback = q.explanation;
        } else if (q.options) {
          var chosen = parseInt(answer);
          isCorrect = q.options[chosen].correct;
          feedback = q.options[chosen].feedback;
        } else {
          isCorrect = (answer === 'suspicious') === !q.isLegit;
          feedback = (q.redFlags || []).join('. ') + '. ' + (q.correctAction || '');
        }

        if (isCorrect) correct++;

        container.querySelector('#se-feedback').innerHTML =
          '<div style="padding:12px;border-radius:6px;border:1px solid ' + (isCorrect ? '#00e676' : '#ff1744') + ';background:' + (isCorrect ? 'rgba(0,230,118,0.08)' : 'rgba(255,23,68,0.08)') + '">' +
            '<div style="font-weight:700;color:' + (isCorrect ? '#00e676' : '#ff1744') + ';margin-bottom:4px">' + (isCorrect ? 'CORRECT' : 'INCORRECT') + '</div>' +
            '<div style="font-size:.82rem;color:var(--mut);line-height:1.6">' + esc(feedback) + '</div>' +
          '</div>' +
          '<button class="btn sm" id="se-next" style="margin-top:12px">' + (qIdx + 1 < total ? 'Next Question' : 'See Results') + '</button>';

        container.querySelector('#se-answers').querySelectorAll('button').forEach(function(b) { b.disabled = true; });

        container.querySelector('#se-next').onclick = function() {
          qIdx++;
          if (qIdx < total) showQuestion();
          else showResults();
        };
      };
    }

    function showResults() {
      var pct = Math.round(correct / total * 100);
      scores[scenario.id] = Math.max(scores[scenario.id] || 0, pct);
      saveScores();

      container.innerHTML =
        '<div style="max-width:600px;text-align:center;margin:40px auto">' +
          '<div style="font-size:3rem;font-weight:700;color:' + (pct >= 80 ? '#00e676' : pct >= 50 ? '#ffd600' : '#ff1744') + '">' + pct + '%</div>' +
          '<div style="font-size:1.1rem;font-weight:600;margin:8px 0">' + correct + ' / ' + total + ' correct</div>' +
          '<div style="font-size:.85rem;color:var(--mut);margin-bottom:16px">' +
            (pct >= 80 ? 'Excellent! You have strong social engineering awareness.' : pct >= 50 ? 'Good start, but review the scenarios you missed.' : 'You need more training. Review the Manipulation Tactics tab.') +
          '</div>' +
          '<div style="margin-bottom:16px;padding:12px;background:var(--card);border:1px solid var(--line);border-radius:6px;text-align:left">' +
            '<div style="font-size:.82rem;font-weight:600;margin-bottom:4px">Real-world example:</div>' +
            '<div style="font-size:.78rem;color:var(--mut);line-height:1.5">' + esc(scenario.realWorld) + '</div>' +
          '</div>' +
          '<div style="display:flex;gap:8px;justify-content:center">' +
            '<button class="btn sm" id="se-retry">Try Again</button>' +
            '<button class="btn sm ghost" id="se-back2">All Scenarios</button>' +
          '</div>' +
        '</div>';

      container.querySelector('#se-retry').onclick = function() { qIdx = 0; correct = 0; showQuestion(); };
      container.querySelector('#se-back2').onclick = function() { renderScenariosTab(container); };
    }

    showQuestion();
  }

  function renderTacticsTab(container) {
    container.innerHTML =
      '<h2 class="pg-h2">Manipulation Tactics</h2>' +
      '<p class="muted" style="margin-bottom:16px">Understanding these psychological principles is your best defense against social engineering.</p>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px">' +
      TACTICS.map(function(t) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px">' +
          '<div style="font-weight:700;font-size:.95rem;color:var(--acc);margin-bottom:6px">' + esc(t.name) + '</div>' +
          '<div style="font-size:.82rem;color:var(--mut);line-height:1.6;margin-bottom:10px">' + esc(t.desc) + '</div>' +
          '<div style="font-size:.75rem;font-weight:600;margin-bottom:4px">Common phrases:</div>' +
          '<ul style="margin:0;padding-left:16px;font-size:.78rem;color:var(--mut)">' +
            t.examples.map(function(ex) { return '<li style="margin:2px 0">"' + esc(ex) + '"</li>'; }).join('') +
          '</ul>' +
        '</div>';
      }).join('') +
      '</div>';
  }

  function renderScoresTab(container) {
    var attempted = Object.keys(scores).length;
    var totalScenarios = SCENARIOS.length;
    var avgScore = attempted > 0 ? Math.round(Object.values(scores).reduce(function(a, b) { return a + b; }, 0) / attempted) : 0;

    container.innerHTML =
      '<h2 class="pg-h2">Your Scores</h2>' +
      '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px">' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px 20px">' +
          '<div style="font-size:1.6rem;font-weight:700;color:' + (avgScore >= 80 ? '#00e676' : avgScore >= 50 ? '#ffd600' : '#ff1744') + '">' + avgScore + '%</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">AVERAGE SCORE</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px 20px">' +
          '<div style="font-size:1.6rem;font-weight:700">' + attempted + '/' + totalScenarios + '</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">COMPLETED</div></div>' +
      '</div>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.8rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">Scenario</th>' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">Category</th>' +
        '<th style="padding:6px;text-align:center;color:var(--mut)">Score</th>' +
      '</tr></thead><tbody>' +
      SCENARIOS.map(function(s) {
        var score = scores[s.id];
        return '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:6px">' + esc(s.name) + '</td>' +
          '<td style="padding:6px;color:var(--mut)">' + esc(s.category) + '</td>' +
          '<td style="padding:6px;text-align:center;color:' + (score === undefined ? 'var(--mut)' : score >= 80 ? '#00e676' : score >= 50 ? '#ffd600' : '#ff1744') + ';font-weight:600">' + (score !== undefined ? score + '%' : '--') + '</td></tr>';
      }).join('') +
      '</tbody></table></div>' +
      '<div style="margin-top:16px"><button class="btn sm ghost" id="se-reset">Reset All Scores</button></div>';

    container.querySelector('#se-reset').onclick = function() { scores = {}; saveScores(); render(); };
  }

  function renderPolicyTab(container) {
    var weakAreas = [];
    SCENARIOS.forEach(function(s) {
      if (scores[s.id] !== undefined && scores[s.id] < 70) weakAreas.push(s.category);
    });

    container.innerHTML =
      '<h2 class="pg-h2">Security Awareness Policy Generator</h2>' +
      '<p class="muted" style="margin-bottom:12px">Generate an anti-social-engineering policy based on your training results.</p>' +
      '<button class="btn sm" id="se-gen-policy">Generate Policy</button>' +
      '<pre class="tk-out" id="se-policy-out" style="margin-top:12px;max-height:500px;overflow-y:auto;white-space:pre-wrap"></pre>';

    container.querySelector('#se-gen-policy').onclick = function() {
      var policy = '=== ANTI-SOCIAL ENGINEERING POLICY ===\n';
      policy += 'Generated: ' + new Date().toISOString().split('T')[0] + '\n\n';
      policy += '1. EMAIL SECURITY\n';
      policy += '   - Never click links in unexpected emails. Navigate to websites directly.\n';
      policy += '   - Verify sender identity by checking the actual email domain, not display name.\n';
      policy += '   - Report all suspicious emails to security@company.com immediately.\n';
      policy += '   - Do not open attachments from unknown senders.\n\n';
      policy += '2. PHONE/VOICE SECURITY\n';
      policy += '   - Never provide passwords, PINs, or MFA codes to callers.\n';
      policy += '   - Verify caller identity by calling back on a known number.\n';
      policy += '   - IT will never ask for your password over the phone.\n\n';
      policy += '3. FINANCIAL CONTROLS\n';
      policy += '   - All wire transfers over $10,000 require verbal confirmation via known phone number.\n';
      policy += '   - No financial requests should bypass established approval chains.\n';
      policy += '   - "Confidential" or "urgent" requests that bypass controls are red flags.\n\n';
      policy += '4. PHYSICAL SECURITY\n';
      policy += '   - Never hold doors for unbadged individuals.\n';
      policy += '   - Report unknown USB drives to security. Never plug them in.\n';
      policy += '   - Challenge unfamiliar individuals in restricted areas.\n\n';
      policy += '5. CREDENTIAL PROTECTION\n';
      policy += '   - Never share credentials via email, chat, or phone.\n';
      policy += '   - Verify all credential requests through a separate communication channel.\n';
      policy += '   - Use password managers and MFA on all accounts.\n\n';
      policy += '6. VENDOR/THIRD-PARTY\n';
      policy += '   - Verify vendor requests through established contacts.\n';
      policy += '   - Never provide system credentials to vendors for their migrations.\n';
      policy += '   - Report vendor credential requests to IT security.\n\n';
      if (weakAreas.length > 0) {
        policy += '7. IDENTIFIED WEAK AREAS (from training)\n';
        weakAreas.forEach(function(area) {
          policy += '   - Additional training recommended for: ' + area + '\n';
        });
      }
      policy += '\n--- REPORTING ---\n';
      policy += 'To report a suspected social engineering attempt:\n';
      policy += '  1. Do not engage further with the attacker\n';
      policy += '  2. Document what happened (screenshots, caller ID, timestamps)\n';
      policy += '  3. Contact IT Security immediately\n';
      policy += '  4. Preserve any evidence (emails, voicemails, USB drives)\n';
      container.querySelector('#se-policy-out').textContent = policy;
    };
  }

  render();
}
