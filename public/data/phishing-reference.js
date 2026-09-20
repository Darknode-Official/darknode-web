// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
//
// Phishing & Social Engineering Campaigns — Comprehensive Reference
// Email anatomy, authentication (SPF/DKIM/DMARC), pretexts, detection,
// infrastructure, and simulation metrics.

// ============================================================================
// EMAIL HEADER ANALYSIS
// ============================================================================
export const EMAIL_HEADER_ANALYSIS = {
  critical_headers: [
    { header: "From", description: "Display sender address. Easily spoofed — never trust alone.", check: "Compare with Return-Path and envelope sender" },
    { header: "Return-Path", description: "Envelope sender (where bounces go). Set by sending MTA, harder to forge than From.", check: "Should match or align with From domain" },
    { header: "Received", description: "Each mail server adds a Received header (bottom = origin, top = most recent). Chain of custody for the email.", check: "Trace from bottom up. Look for suspicious hops, unexpected countries, forged entries." },
    { header: "Authentication-Results", description: "SPF, DKIM, and DMARC verification results added by receiving server.", check: "Look for spf=pass, dkim=pass, dmarc=pass. Any fail is suspicious." },
    { header: "X-Originating-IP", description: "IP address of the sender (added by some providers like Outlook.com).", check: "Geolocation of IP should match expected sender location" },
    { header: "Message-ID", description: "Unique identifier for the email. Format: <unique@domain>.", check: "Domain in Message-ID should match sending infrastructure" },
    { header: "Reply-To", description: "Address where replies go. Often different from From in phishing.", check: "Mismatch between From and Reply-To is a red flag" },
    { header: "X-Mailer / User-Agent", description: "Email client used to send.", check: "Unusual or generic mailer names (Python, PHP mailer) suggest automated sending" },
    { header: "MIME-Version", description: "MIME version (always 1.0). Presence confirms MIME structure.", check: "Standard header" },
    { header: "Content-Type", description: "Body format and encoding.", check: "multipart/mixed with attachments, text/html for phishing pages" },
    { header: "X-Spam-Status", description: "Spam filter results.", check: "Score and triggered rules" },
    { header: "DKIM-Signature", description: "Cryptographic signature over header/body fields.", check: "d= domain should match From domain or be authorized" },
    { header: "ARC-Authentication-Results", description: "Authenticated Received Chain — preserves auth results across forwards.", check: "Important for forwarded emails that would otherwise fail DMARC" },
    { header: "List-Unsubscribe", description: "Unsubscribe mechanism.", check: "Phishing often lacks this; legitimate bulk email requires it" },
  ],
  red_flags: [
    "Return-Path doesn't match From domain",
    "SPF/DKIM/DMARC fail or softfail",
    "Received chain shows unexpected origin (different country, cloud provider)",
    "Reply-To different from From",
    "Message-ID domain doesn't match sender",
    "X-Originating-IP from unexpected location",
    "Multiple Received headers from the same server (looping)",
    "Missing or malformed DKIM-Signature",
    "Unusual X-Mailer (PHPMailer, Python/smtplib, mass mail tools)",
    "Date/time doesn't match timezone of purported sender",
    "Encoded subject line with unusual character sets",
    "Content-Type mismatch (HTML email claiming to be plain text)",
  ],
};

// ============================================================================
// EMAIL AUTHENTICATION (SPF, DKIM, DMARC)
// ============================================================================
export const EMAIL_AUTH = {
  spf: {
    name: "Sender Policy Framework",
    description: "DNS TXT record listing authorized mail servers for a domain. Receiving server checks if the sending IP is authorized.",
    record_format: "v=spf1 [mechanisms] [modifiers]",
    mechanisms: [
      { mechanism: "ip4:192.168.1.0/24", description: "Authorize specific IPv4 range" },
      { mechanism: "ip6:2001:db8::/32", description: "Authorize specific IPv6 range" },
      { mechanism: "a", description: "Authorize the domain's A record IPs" },
      { mechanism: "mx", description: "Authorize the domain's MX record IPs" },
      { mechanism: "include:_spf.google.com", description: "Include another domain's SPF record (delegation)" },
      { mechanism: "redirect=_spf.example.com", description: "Replace entire SPF with another domain's record" },
      { mechanism: "exists:%{i}._spf.example.com", description: "Macro-based IP lookup" },
    ],
    qualifiers: [
      { qualifier: "+", meaning: "Pass (default)" },
      { qualifier: "-", meaning: "Fail (hard fail — reject)" },
      { qualifier: "~", meaning: "SoftFail (accept but mark)" },
      { qualifier: "?", meaning: "Neutral (no assertion)" },
    ],
    examples: [
      { record: "v=spf1 include:_spf.google.com ~all", description: "Google Workspace — authorize Google's servers, softfail all others" },
      { record: "v=spf1 ip4:203.0.113.0/24 include:sendgrid.net -all", description: "Own servers + SendGrid, hard fail others" },
      { record: "v=spf1 -all", description: "Domain sends no email — reject everything" },
    ],
    bypass_techniques: [
      "Send from an IP included in SPF (compromised mail server)",
      "Use a subdomain without SPF record",
      "SPF only checks envelope sender (Return-Path), not header From",
      "Some receivers only implement softfail, not hard reject",
      "DNS lookup limit (10 lookups) — exceeding causes permerror (treated as none)",
    ],
  },
  dkim: {
    name: "DomainKeys Identified Mail",
    description: "Cryptographic signature over email headers and body. Signing domain publishes public key in DNS. Receiving server verifies the signature.",
    signature_fields: [
      { tag: "v", description: "Version (always 1)" },
      { tag: "a", description: "Algorithm (rsa-sha256 or ed25519-sha256)" },
      { tag: "d", description: "Signing domain — this is the identity being asserted" },
      { tag: "s", description: "Selector — used to look up public key: s._domainkey.d" },
      { tag: "h", description: "Signed headers list (from:to:subject:date:message-id etc.)" },
      { tag: "bh", description: "Body hash (base64)" },
      { tag: "b", description: "Signature value (base64)" },
      { tag: "c", description: "Canonicalization: relaxed/relaxed or simple/simple" },
      { tag: "t", description: "Timestamp" },
      { tag: "x", description: "Expiration time" },
    ],
    dns_record_format: "selector._domainkey.domain.com TXT 'v=DKIM1; k=rsa; p=<base64_public_key>'",
    bypass_techniques: [
      "DKIM only signs specific headers — unsigned headers can be forged",
      "Replay attacks: take a legitimately signed email, modify unsigned parts, resend",
      "l= tag (body length) allows appending content after the signed portion",
      "Weak keys (512-bit RSA) can be factored",
      "Domain might sign with a different d= than the From header domain",
    ],
  },
  dmarc: {
    name: "Domain-based Message Authentication, Reporting & Conformance",
    description: "Policy layer that combines SPF and DKIM. Requires alignment between From header domain and SPF/DKIM authenticated domain. Tells receivers what to do on failure.",
    record_format: "_dmarc.domain.com TXT 'v=DMARC1; p=<policy>; ...'",
    tags: [
      { tag: "p", description: "Policy for domain: none (monitor), quarantine (spam), reject (block)", required: true },
      { tag: "sp", description: "Policy for subdomains (inherits p if not set)" },
      { tag: "rua", description: "Aggregate report recipients (mailto:dmarc@domain.com)" },
      { tag: "ruf", description: "Forensic report recipients (detailed failure reports)" },
      { tag: "pct", description: "Percentage of messages to apply policy to (0-100, default 100)" },
      { tag: "adkim", description: "DKIM alignment mode: r=relaxed (subdomains OK), s=strict (exact match)" },
      { tag: "aspf", description: "SPF alignment mode: r=relaxed, s=strict" },
      { tag: "fo", description: "Failure reporting options: 0=all fail, 1=any fail, d=DKIM fail, s=SPF fail" },
    ],
    alignment: {
      description: "DMARC checks that the From header domain aligns with the domain authenticated by SPF or DKIM.",
      spf_alignment: "From header domain must match the Return-Path (envelope from) domain",
      dkim_alignment: "From header domain must match the DKIM d= domain",
      relaxed: "Organizational domain match (subdomains OK: mail.example.com aligns with example.com)",
      strict: "Exact domain match required",
    },
    bypass_techniques: [
      "p=none policy — domain is only monitoring, not enforcing",
      "pct=0 — policy applies to 0% of messages (effectively none)",
      "Subdomain without sp= inherits p=none from parent",
      "Use a look-alike domain (not the actual domain — DMARC won't apply)",
      "Exploit forwarding — forwarded emails fail SPF, and if DKIM breaks, DMARC fails",
      "Find subdomain with relaxed alignment and no MX/SPF records",
    ],
    examples: [
      { record: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com; adkim=s; aspf=s", description: "Strict enforcement — reject failures, strict alignment, reports to both addresses" },
      { record: "v=DMARC1; p=none; rua=mailto:dmarc@example.com", description: "Monitor only — collect reports but don't block anything (deployment phase 1)" },
      { record: "v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com", description: "Quarantine 50% of failures (gradual rollout)" },
    ],
  },
};

// ============================================================================
// PHISHING INFRASTRUCTURE
// ============================================================================
export const PHISHING_INFRASTRUCTURE = [
  {
    tool: "GoPhish",
    type: "Phishing simulation platform",
    description: "Open-source phishing framework for authorized security assessments. Web UI for campaign management, email templates, landing pages, and result tracking.",
    features: ["Campaign management with scheduling", "Email template editor with tracking pixel", "Landing page cloning", "User/group management", "Real-time result dashboard", "CSV import for targets", "SMTP profile configuration"],
    setup_notes: "Requires own SMTP relay. Use with authorization only. Change default admin password.",
    url: "github.com/gophish/gophish",
  },
  {
    tool: "Evilginx2",
    type: "Advanced phishing proxy (MitM)",
    description: "Man-in-the-middle attack framework for phishing. Acts as a reverse proxy between victim and real site, capturing credentials AND session tokens (bypasses 2FA).",
    features: ["Transparent reverse proxy", "Captures session cookies (bypasses MFA)", "Phishlet templates for major sites", "Lure URL generation", "TLS certificate auto-provisioning"],
    setup_notes: "Requires domain with DNS control. Points victim to proxy, proxy forwards to real site. Captures everything including auth tokens.",
  },
  {
    tool: "Modlishka",
    type: "Reverse proxy phishing",
    description: "Similar to Evilginx — reverse proxy that captures credentials and 2FA tokens in real-time. Written in Go.",
    features: ["Real-time credential harvesting", "2FA token capture", "Automated TLS", "Pattern-based URL handling"],
  },
  {
    tool: "SocialFish",
    type: "Phishing page generator",
    description: "Automated phishing page generator with built-in templates for popular services.",
    features: ["Pre-built templates", "Credential logging", "Ngrok integration for public URL", "Web dashboard"],
  },
  {
    tool: "King Phisher",
    type: "Enterprise phishing campaign toolkit",
    description: "Phishing campaign toolkit with server/client architecture. Supports SMS phishing and has advanced reporting.",
    features: ["Campaign management", "Jinja2 email templates", "SPF/DKIM checking", "Two-factor authentication tracking", "REST API", "Plugin system"],
  },
];

// ============================================================================
// PHISHING PRETEXTS (TEMPLATES)
// ============================================================================
export const PHISHING_PRETEXTS = [
  // IT / Helpdesk
  { category: "IT Helpdesk", name: "Password Expiration", subject: "Action Required: Your password expires in 24 hours", description: "Warns user their password is expiring and links to a fake password reset page. Creates urgency with 24-hour deadline.", effectiveness: "high", red_flags: ["Generic greeting", "Urgency", "External link for internal system"] },
  { category: "IT Helpdesk", name: "MFA Setup Required", subject: "Security Update: Enable Multi-Factor Authentication", description: "Claims organization is requiring MFA and links to fake enrollment page that captures credentials.", effectiveness: "high", red_flags: ["Links to external domain", "Asks for current password during setup"] },
  { category: "IT Helpdesk", name: "Mailbox Full", subject: "Your mailbox is almost full — action required", description: "Claims user's mailbox is near capacity, links to fake portal to 'verify' account and free space.", effectiveness: "medium", red_flags: ["Vague storage numbers", "External cleanup link"] },
  { category: "IT Helpdesk", name: "VPN Update Required", subject: "Critical: VPN Client Update Required for Remote Access", description: "Claims VPN client needs urgent update, links to malicious download disguised as VPN installer.", effectiveness: "medium", red_flags: ["Asks to download from external link", "Urgency"] },
  { category: "IT Helpdesk", name: "Account Verification", subject: "Unusual sign-in activity detected on your account", description: "Mimics Microsoft/Google security alert about suspicious login, links to credential capture page.", effectiveness: "very_high", red_flags: ["Generic 'unusual activity'", "Click to verify link"] },
  { category: "IT Helpdesk", name: "Software License Expiry", subject: "Your Microsoft 365 license is expiring", description: "Claims Office/M365 license is expiring and needs reactivation. Links to fake Microsoft login.", effectiveness: "high", red_flags: ["Pressure to act quickly", "External Microsoft-looking domain"] },

  // CEO Fraud / BEC
  { category: "CEO Fraud", name: "Wire Transfer Request", subject: "Urgent: Wire transfer needed today", description: "Spoofs CEO email to CFO/finance, requests urgent wire transfer for confidential acquisition or vendor payment.", effectiveness: "high", red_flags: ["Urgency", "Secrecy request", "Different Reply-To", "Unusual request from executive"] },
  { category: "CEO Fraud", name: "Gift Card Request", subject: "Quick favor needed", description: "CEO asks employee to buy gift cards for client/employee appreciation. Requests card numbers by email.", effectiveness: "medium", red_flags: ["Gift card request via email", "Asks not to call", "Unusual for executive"] },
  { category: "CEO Fraud", name: "Vendor Payment Change", subject: "Updated banking details for invoice #INV-2024-0847", description: "Compromised or spoofed vendor email with updated bank details for upcoming payment.", effectiveness: "high", red_flags: ["Changed banking details", "Urgency before payment date", "Slight email variation"] },
  { category: "CEO Fraud", name: "Payroll Redirect", subject: "Please update my direct deposit information", description: "Employee or executive asks HR to change their direct deposit bank account.", effectiveness: "medium", red_flags: ["Request via email only", "New bank details", "Timing near payday"] },

  // Invoice / Financial
  { category: "Invoice", name: "Overdue Invoice", subject: "OVERDUE: Invoice #38291 — Payment Required", description: "Fake invoice attachment (PDF with macro or link) claiming overdue payment.", effectiveness: "medium", red_flags: ["Unknown vendor", "Attachment", "Urgency", "Threatening collections"] },
  { category: "Invoice", name: "Purchase Order", subject: "PO #72849 — Please review and confirm", description: "Fake purchase order requiring review. Attachment contains malware or links to credential page.", effectiveness: "medium", red_flags: ["Unexpected PO", "Attachment from unknown sender"] },
  { category: "Invoice", name: "Tax Document", subject: "Your W-2 / Tax Document is Ready", description: "Seasonal tax document phishing. Links to fake portal or delivers malicious attachment.", effectiveness: "high", red_flags: ["Seasonal timing", "Asks for SSN/tax ID", "External portal link"] },

  // Delivery / Shipping
  { category: "Delivery", name: "Package Delivery", subject: "Your package could not be delivered — action required", description: "Fake delivery notification from UPS/FedEx/DHL. Links to tracking page that captures credentials or delivers malware.", effectiveness: "high", red_flags: ["No specific tracking number", "Unexpected delivery", "Link to non-carrier domain"] },
  { category: "Delivery", name: "Customs Hold", subject: "Package held at customs — payment required", description: "Claims package is held and requires customs fee payment via link.", effectiveness: "medium", red_flags: ["Customs fee via email", "Unfamiliar sender"] },
  { category: "Delivery", name: "Order Confirmation", subject: "Order Confirmation #AM-7291847", description: "Fake Amazon/retailer order confirmation for expensive item user didn't buy. 'Click to cancel' leads to credential capture.", effectiveness: "high", red_flags: ["Order you didn't place", "Urgency to 'cancel'", "Emotional trigger (charge)"] },

  // Banking / Financial
  { category: "Banking", name: "Suspicious Transaction", subject: "Fraud Alert: Suspicious transaction on your account", description: "Fake bank alert about unauthorized transaction. Links to fake banking portal.", effectiveness: "very_high", red_flags: ["Generic bank name", "Links to non-bank domain", "Asks for full credentials"] },
  { category: "Banking", name: "Account Locked", subject: "Your account has been temporarily limited", description: "Claims account is locked due to suspicious activity. Requires 'verification' to unlock.", effectiveness: "high", red_flags: ["Urgency", "Verification link", "Generic greeting"] },
  { category: "Banking", name: "Tax Refund", subject: "Your tax refund of $3,847.00 is ready", description: "Government tax refund notification. Links to fake government portal asking for bank details.", effectiveness: "high", red_flags: ["Government doesn't email about refunds", "Asks for bank details"] },

  // Social Media
  { category: "Social Media", name: "Login Alert", subject: "New login to your account from unknown device", description: "Fake Instagram/Facebook/LinkedIn login alert. Links to credential capture page.", effectiveness: "high", red_flags: ["Non-official sender domain", "Generic device info"] },
  { category: "Social Media", name: "Account Verification", subject: "Verify your identity to keep your account", description: "Claims account will be disabled without verification. Targets influencers and business accounts.", effectiveness: "medium", red_flags: ["Threat of account closure", "Asks for password"] },
  { category: "Social Media", name: "Copyright Violation", subject: "Your post has been reported for copyright infringement", description: "Claims content violates copyright, links to fake appeals form.", effectiveness: "medium", red_flags: ["Fear trigger", "External appeal link"] },

  // Cloud Services
  { category: "Cloud", name: "Shared Document", subject: "John shared a document with you", description: "Fake Google Docs/OneDrive/Dropbox share notification. Links to OAuth consent phishing or fake login.", effectiveness: "very_high", red_flags: ["Unexpected share from known contact", "Asks for login on external page"] },
  { category: "Cloud", name: "Storage Full", subject: "Your Google Drive storage is full", description: "Claims cloud storage is full, offers to 'upgrade' via link to credential capture page.", effectiveness: "medium", red_flags: ["External upgrade link", "Urgency"] },

  // HR / Employee
  { category: "HR", name: "Benefits Enrollment", subject: "Open Enrollment: Update your benefits by Friday", description: "Seasonal benefits enrollment phishing. Links to fake HR portal.", effectiveness: "high", red_flags: ["Tight deadline", "External HR link", "Asks for SSN/personal info"] },
  { category: "HR", name: "Policy Update", subject: "Updated Employee Handbook — Review Required", description: "Fake policy update requiring acknowledgment. Attachment or link to credential page.", effectiveness: "medium", red_flags: ["Attachment from external sender", "Urgency to acknowledge"] },
  { category: "HR", name: "Performance Review", subject: "Your performance review is ready for viewing", description: "Claims annual review is available. Links to fake HR portal to capture credentials.", effectiveness: "high", red_flags: ["Emotional trigger (review)", "External portal link"] },
];

// ============================================================================
// ADVANCED PHISHING TECHNIQUES
// ============================================================================
export const ADVANCED_PHISHING = [
  {
    name: "Homograph Attack (IDN Spoofing)",
    description: "Register domain using Unicode characters that look identical to ASCII in browsers. Example: xn--pple-43d.com displays as аpple.com (Cyrillic 'а').",
    examples: ["аpple.com (Cyrillic а)", "gооgle.com (Cyrillic о)", "раypal.com (Cyrillic а, р)"],
    defense: "Modern browsers show Punycode (xn--) for mixed-script domains. Users should check certificate details.",
  },
  {
    name: "Browser-in-the-Browser (BitB)",
    description: "Create a fake browser popup window within the webpage using HTML/CSS/JS. Mimics OAuth login popup (Google, Microsoft, Apple). URL bar shows the legitimate domain but is actually a rendered image.",
    indicators: ["Popup can't be moved outside the browser window", "Popup can't be resized independently", "Right-click doesn't show browser context menu", "URL bar is not interactive"],
    defense: "Try dragging the popup outside the browser window. Real popups move independently.",
  },
  {
    name: "QR Code Phishing (Quishing)",
    description: "Embed malicious URL in a QR code. Bypasses email link scanning since the URL is in an image. User scans with phone, which may have less security than desktop.",
    delivery: ["Email with QR code image", "Physical QR codes in public places", "QR codes replacing legitimate ones (overlaid stickers)"],
    defense: "Preview QR code URL before opening. QR scanner apps that show URL first.",
  },
  {
    name: "OAuth Consent Phishing",
    description: "Create a malicious OAuth app that requests permissions to read email, contacts, files. Victim clicks 'Allow' on legitimate Google/Microsoft consent screen. No password captured — attacker gets API token.",
    permissions_requested: ["Read email", "Access contacts", "Read/write files", "Send email on behalf of user"],
    defense: "Review OAuth app permissions carefully. Revoke unknown app permissions in account settings.",
  },
  {
    name: "Adversary-in-the-Middle (AiTM) Phishing",
    description: "Real-time proxy between victim and legitimate site (Evilginx2). Captures credentials AND session cookies. Bypasses all forms of 2FA/MFA except FIDO2 hardware keys.",
    bypasses: ["TOTP (Google Authenticator)", "SMS codes", "Push notifications (partial — victim approves on real site)", "Email-based OTP"],
    does_not_bypass: ["FIDO2/WebAuthn hardware keys (origin-bound)", "Passkeys"],
    defense: "FIDO2 hardware security keys, passkeys, conditional access policies checking device compliance",
  },
  {
    name: "Vishing (Voice Phishing)",
    description: "Phone-based social engineering. Caller impersonates IT support, bank, government agency. May use caller ID spoofing to show legitimate number.",
    common_scenarios: ["IT helpdesk requesting remote access or credentials", "Bank fraud department about suspicious transaction", "IRS/tax authority about unpaid taxes", "Tech support scam about computer virus", "CEO urgently needing a wire transfer (deepfake voice)"],
    defense: "Verify by calling back on known number. Never give credentials over phone.",
  },
  {
    name: "Smishing (SMS Phishing)",
    description: "Phishing via SMS/text messages. Often impersonates banks, delivery services, or government agencies. Short URLs common.",
    common_pretexts: ["Package delivery notification", "Bank fraud alert", "COVID/health test results", "Prize/sweepstakes winner", "Account verification code request"],
    defense: "Don't click links in unexpected texts. Verify via official app/website.",
  },
  {
    name: "Callback Phishing (BazarCall)",
    description: "Email with no links or attachments — just a phone number to call about a fake subscription/charge. When victim calls, attacker guides them to install remote access tool or malware.",
    defense: "Don't call numbers from unexpected emails. Verify charges through official channels.",
  },
  {
    name: "MFA Fatigue / Push Bombing",
    description: "Repeatedly trigger MFA push notifications to victim's phone until they approve to stop the annoyance. Works against push-based MFA without number matching.",
    defense: "MFA with number matching requirement. Report unexpected push notifications. Use FIDO2 instead.",
  },
  {
    name: "SEO Poisoning",
    description: "Create phishing pages optimized for search engines. When users search for 'company login' or 'download software', malicious page appears in results.",
    defense: "Bookmark legitimate login pages. Verify URL carefully from search results.",
  },
  {
    name: "Watering Hole",
    description: "Compromise a website frequently visited by the target group. Inject malicious code that targets visitors matching specific criteria (IP range, user agent).",
    defense: "Keep browsers and plugins updated. Network monitoring for unusual post-browse connections.",
  },
];

// ============================================================================
// PHISHING DETECTION INDICATORS
// ============================================================================
export const PHISHING_INDICATORS = {
  email_indicators: [
    "Sender domain doesn't match the claimed organization",
    "Display name spoofing: 'IT Support <random@gmail.com>'",
    "Reply-To different from From address",
    "SPF/DKIM/DMARC failures in Authentication-Results header",
    "Urgent language: 'immediate action required', 'your account will be suspended'",
    "Generic greeting: 'Dear Customer' instead of name",
    "Grammar and spelling errors (less common in sophisticated attacks)",
    "Mismatched or suspicious links (hover to check URL)",
    "Shortened URLs (bit.ly, tinyurl, etc.)",
    "Unexpected attachments (especially .exe, .js, .vbs, .docm, .xlsm, .iso, .img)",
    "Request for sensitive information (passwords, SSN, credit card)",
    "Threatening consequences for not acting",
    "Too-good-to-be-true offers (prize, refund, free gift)",
    "Inconsistent branding (wrong logo, colors, fonts)",
    "HTML email with image-only content (evades text analysis)",
    "Embedded forms in email body (legitimate services don't do this)",
    "Unusual sending time (3am from a business contact)",
    "cc/bcc to many recipients with no relationship",
    "Email thread hijacking (reply to legitimate thread with malicious content)",
    "Calendar invite phishing (malicious link in calendar event)",
  ],
  url_indicators: [
    "Domain similar to legitimate but different (micros0ft.com, g00gle.com)",
    "Legitimate domain as subdomain: microsoft.com.evil.com",
    "Extra path components: evil.com/microsoft.com/login",
    "IP address instead of domain name",
    "HTTP instead of HTTPS for login pages",
    "Recently registered domain (whois creation date < 30 days)",
    "Free hosting services (*.000webhostapp.com, *.netlify.app for phishing)",
    "URL with @ symbol: http://legitimate.com@evil.com",
    "Encoded characters in URL (%20, %2F, etc.)",
    "Excessive subdomains: login.microsoft.secure.verify.evil.com",
    "Punycode domain (xn-- prefix) with visually similar characters",
    "URL shortener (can't see actual destination)",
    "data: URI in link (data:text/html;base64,...) — opens inline HTML",
    "JavaScript in URL (javascript:...)",
    "Redirect chains (multiple redirects before final page)",
  ],
  attachment_indicators: [
    ".exe, .scr, .pif, .com — direct executables",
    ".js, .jse, .vbs, .vbe, .wsf, .wsh — Windows script files",
    ".docm, .xlsm, .pptm — Office files with macros",
    ".iso, .img — disk images (bypass Mark-of-the-Web on Windows)",
    ".lnk — Windows shortcut (can execute commands)",
    ".html, .htm — local HTML file with JavaScript (HTA)",
    ".hta — HTML Application (runs with full privileges)",
    ".svg — can contain embedded JavaScript",
    ".zip with password — evades antivirus scanning",
    "Double extension: report.pdf.exe, document.docx.js",
    "Right-to-Left Override character hiding real extension",
    "Very small file size for expected document type",
    "OneNote (.one) files with embedded scripts (2023 trend)",
  ],
  website_indicators: [
    "Missing or invalid SSL certificate",
    "Certificate issued by free CA (Let's Encrypt) for bank/enterprise login",
    "No favicon or generic favicon for major brand",
    "Only the login form works — other links are dead",
    "Accepts any credentials (always shows error or succeeds regardless)",
    "Form submits to different domain than page",
    "Right-click disabled or developer tools blocked",
    "Page source contains obfuscated JavaScript",
    "Missing legitimate site elements (footer, terms, privacy policy)",
    "Excessive use of frames/iframes",
    "Popup windows imitating browser chrome (BitB attack)",
  ],
};

// ============================================================================
// PHISHING SIMULATION METRICS
// ============================================================================
export const SIMULATION_METRICS = {
  key_metrics: [
    { metric: "Click Rate", description: "Percentage of recipients who clicked the phishing link", benchmark_low: "< 5%", benchmark_avg: "10-20%", benchmark_high: "> 30%", notes: "Varies greatly by pretext sophistication and targeting" },
    { metric: "Submit Rate", description: "Percentage who submitted credentials on the phishing page", benchmark_low: "< 2%", benchmark_avg: "3-8%", benchmark_high: "> 15%", notes: "The critical metric — actual credential compromise" },
    { metric: "Report Rate", description: "Percentage who reported the email as phishing", benchmark_low: "< 10%", benchmark_avg: "15-30%", benchmark_high: "> 50%", notes: "Measures security awareness culture. Goal: higher is better." },
    { metric: "Open Rate", description: "Percentage who opened the email", benchmark_low: "< 30%", benchmark_avg: "50-70%", benchmark_high: "> 80%", notes: "Useful but less actionable — opening alone isn't compromise" },
    { metric: "Time to First Click", description: "How quickly the first person clicked", benchmark_low: "> 2 hours", benchmark_avg: "15-60 minutes", benchmark_high: "< 5 minutes", notes: "Fast clicks indicate low caution" },
    { metric: "Time to First Report", description: "How quickly someone reported it", benchmark_low: "> 4 hours", benchmark_avg: "30-120 minutes", benchmark_high: "< 10 minutes", notes: "Faster reporting = better incident response" },
    { metric: "Repeat Offenders", description: "Users who fall for multiple simulations", notes: "Focus training on this group. Track improvement over time." },
  ],
  industry_benchmarks: [
    { industry: "Healthcare", avg_click_rate: "27%", notes: "High due to urgency-driven culture" },
    { industry: "Education", avg_click_rate: "25%", notes: "Mixed technical literacy" },
    { industry: "Government", avg_click_rate: "22%", notes: "Improving with awareness programs" },
    { industry: "Finance", avg_click_rate: "12%", notes: "Strong security culture, regular training" },
    { industry: "Technology", avg_click_rate: "9%", notes: "Technically savvy workforce" },
    { industry: "Legal", avg_click_rate: "20%", notes: "Document-heavy workflows increase risk" },
    { industry: "Manufacturing", avg_click_rate: "24%", notes: "Less cybersecurity focus historically" },
    { industry: "Retail", avg_click_rate: "21%", notes: "High turnover, varied training" },
  ],
  best_practices: [
    "Run simulations monthly (not just annually)",
    "Vary pretexts — don't repeat the same template",
    "Include all employee levels including executives",
    "Provide immediate training when someone fails (teachable moment)",
    "Track improvement trends over quarters, not individual failures",
    "Don't punish failures — use as learning opportunities",
    "Simulate current threat trends (what's actually being used)",
    "Include mobile-focused attacks (SMS, QR codes)",
    "Test at different times (business hours, weekends, holidays)",
    "Measure report rate as primary success metric (not just click rate)",
    "Calibrate difficulty — too easy doesn't test, too hard demoralizes",
  ],
};

export default {
  EMAIL_HEADER_ANALYSIS,
  EMAIL_AUTH,
  PHISHING_INFRASTRUCTURE,
  PHISHING_PRETEXTS,
  ADVANCED_PHISHING,
  PHISHING_INDICATORS,
  SIMULATION_METRICS,
};
