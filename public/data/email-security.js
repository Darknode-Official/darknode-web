// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Email Security Reference — headers, SPF, DKIM, DMARC, attacks, forensics

export const EMAIL_HEADERS = [
  { header: "From", description: "Sender's display name and email address. Easily spoofed — the header From is what the user sees but is NOT authenticated by default.", security: "Compare with Return-Path, DKIM d= domain, and SPF check domain. Mismatch indicates potential spoofing.", example: "From: John Doe <john@example.com>" },
  { header: "To", description: "Recipient address(es).", security: "BCC recipients won't appear here. Check for mass-mailing indicators.", example: "To: recipient@example.com" },
  { header: "Subject", description: "Email subject line.", security: "Social engineering indicator. Look for urgency, threats, or impersonation patterns.", example: "Subject: URGENT: Your account has been compromised" },
  { header: "Date", description: "When the email was composed.", security: "Compare with Received headers to detect time manipulation. Large discrepancies suggest automated/backdated sending.", example: "Date: Mon, 1 Jan 2026 12:00:00 +0000" },
  { header: "Return-Path", description: "Envelope sender (bounce address). Set by the sending MTA during SMTP MAIL FROM.", security: "This is the authenticated sender for SPF checks. Mismatch between From and Return-Path is common in legitimate email (mailing lists, forwarding) but also in spoofing.", example: "Return-Path: <bounce@sender.example.com>" },
  { header: "Received", description: "Added by each mail server in the relay chain, bottom-to-top (oldest at bottom). Contains server hostname, IP, protocol, timestamp.", security: "Critical for tracing email origin. The bottom-most Received header shows the first server that handled the email. Forged headers can be added, but servers add their own on top. Trust headers from your own infrastructure.", example: "Received: from mail.sender.com (mail.sender.com [93.184.216.34]) by mx.recipient.com (Postfix) with ESMTPS id ABC123; Mon, 1 Jan 2026 12:00:01 +0000" },
  { header: "Message-ID", description: "Unique identifier assigned by the originating mail system.", security: "Should match the domain of the sender. A Message-ID with a different domain than the From address is suspicious. Duplicate Message-IDs across different emails indicate replay attacks.", example: "Message-ID: <abc123@mail.example.com>" },
  { header: "MIME-Version", description: "MIME version used (almost always 1.0).", security: "Unusual or missing MIME-Version can indicate non-standard mail clients.", example: "MIME-Version: 1.0" },
  { header: "Content-Type", description: "Media type of the email body (text/plain, text/html, multipart/mixed, etc.).", security: "multipart/mixed with application/* attachments is common in malware delivery. text/html enables phishing with embedded links and forms.", example: "Content-Type: multipart/mixed; boundary=\"----=_Part_123\"" },
  { header: "Content-Transfer-Encoding", description: "Encoding used for the body (7bit, 8bit, base64, quoted-printable).", security: "Base64-encoded bodies can hide malicious content from simple text scanning.", example: "Content-Transfer-Encoding: base64" },
  { header: "X-Mailer", description: "Email client used to compose the message.", security: "Reveals software and version. Mismatched X-Mailer (e.g., Outlook header from a Linux server) indicates spoofing or automated sending.", example: "X-Mailer: Microsoft Outlook 16.0" },
  { header: "X-Originating-IP", description: "IP address of the client that submitted the email (added by some mail servers like Exchange/Outlook.com).", security: "Reveals the sender's actual IP address, bypassing VPNs and proxies used for the web interface. Valuable for attribution.", example: "X-Originating-IP: [203.0.113.50]" },
  { header: "Authentication-Results", description: "Results of email authentication checks (SPF, DKIM, DMARC) performed by the receiving server.", security: "Shows pass/fail for each authentication method. Multiple Authentication-Results headers may exist from different servers in the chain. Trust only the one added by your own MX.", example: "Authentication-Results: mx.google.com; dkim=pass header.d=example.com; spf=pass (google.com: domain of sender@example.com designates 93.184.216.34 as permitted sender); dmarc=pass (p=REJECT)" },
  { header: "ARC-Authentication-Results", description: "Authenticated Received Chain — preserves authentication results across forwarding hops.", security: "Solves the problem of DKIM/SPF breaking when email is forwarded through mailing lists or forwarding services.", example: "ARC-Authentication-Results: i=1; mx.google.com; dkim=pass header.d=example.com; spf=pass" },
  { header: "ARC-Message-Signature", description: "ARC signature over the message at each hop.", security: "Allows the final receiver to verify the authentication state at each intermediate hop.", example: "ARC-Message-Signature: i=1; a=rsa-sha256; d=google.com; s=arc-20160816; ..." },
  { header: "ARC-Seal", description: "ARC seal that chains ARC sets together.", security: "Prevents tampering with ARC headers by earlier hops.", example: "ARC-Seal: i=1; a=rsa-sha256; t=1704067201; cv=none; d=google.com; s=arc-20160816; ..." },
  { header: "DKIM-Signature", description: "DomainKeys Identified Mail signature. Cryptographically signs specific headers and the body.", security: "Verifies that the email was sent by the domain in d= and that signed headers/body haven't been modified. Check b= (signature), bh= (body hash), d= (signing domain), s= (selector).", example: "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; h=from:to:subject:date:message-id; bh=abc123...; b=xyz789..." },
  { header: "Received-SPF", description: "SPF check result.", security: "Shows whether the sending IP was authorized by the domain's SPF record. Values: pass, fail, softfail, neutral, none, temperror, permerror.", example: "Received-SPF: pass (google.com: domain of sender@example.com designates 93.184.216.34 as permitted sender)" },
  { header: "X-Spam-Status", description: "Spam filter verdict and score (SpamAssassin format).", security: "Shows which spam rules triggered and the total score. Useful for understanding why an email was or wasn't flagged.", example: "X-Spam-Status: No, score=1.2 required=5.0 tests=HTML_MESSAGE,DKIM_SIGNED,DKIM_VALID" },
  { header: "X-Spam-Score", description: "Numeric spam score.", security: "Higher scores indicate more spam-like characteristics.", example: "X-Spam-Score: 1.2" },
  { header: "X-MS-Exchange-Organization-AuthSource", description: "Microsoft Exchange authentication source server.", security: "Reveals internal Exchange server names and organization structure.", example: "X-MS-Exchange-Organization-AuthSource: EXCH01.corp.example.com" },
  { header: "X-MS-Exchange-Organization-SCL", description: "Spam Confidence Level in Microsoft Exchange (0-9, -1=safe).", security: "SCL >= 5 typically goes to Junk. SCL of -1 means the message bypassed filtering (internal or safe sender).", example: "X-MS-Exchange-Organization-SCL: 1" },
  { header: "X-Forefront-Antispam-Report", description: "Microsoft 365 anti-spam report with detailed categorization.", security: "Contains SCL, BCL (bulk complaint level), country of origin, and specific filter actions.", example: "X-Forefront-Antispam-Report: CIP:93.184.216.34;CTRY:US;LANG:en;SCL:1;SRV:;..." },
  { header: "X-Microsoft-Antispam", description: "Microsoft 365 additional anti-spam data.", security: "Includes BCL (bulk confidence level) and PCL (phishing confidence level).", example: "X-Microsoft-Antispam: BCL:0;PCL:0;" },
  { header: "X-Google-DKIM-Signature", description: "Google's internal DKIM signature for Gmail-processed messages.", security: "Added by Google infrastructure; verifies the message passed through Google's servers.", example: "X-Google-DKIM-Signature: v=1; a=rsa-sha256; d=1e100.net; s=20230601; ..." },
  { header: "X-Gm-Message-State", description: "Gmail internal message state tracking.", security: "Opaque value used by Gmail; presence confirms the message was processed by Google.", example: "X-Gm-Message-State: AOJu0Yw..." },
  { header: "List-Unsubscribe", description: "URL or mailto address to unsubscribe from a mailing list.", security: "Legitimate marketing emails should have this. Phishing emails may include a tracking/malicious unsubscribe link.", example: "List-Unsubscribe: <https://example.com/unsub?id=123>, <mailto:unsub@example.com>" },
  { header: "Precedence", description: "Email priority/type: bulk, junk, list.", security: "Bulk/list precedence indicates mass mailing. Should not be present in targeted personal email.", example: "Precedence: bulk" },
  { header: "Reply-To", description: "Address where replies should be sent (can differ from From).", security: "Common in phishing: From appears legitimate but Reply-To goes to attacker's address. Always compare From and Reply-To.", example: "Reply-To: attacker@evil.com" },
  { header: "Sender", description: "The actual sender when different from From (e.g., mailing list manager sending on behalf of a user).", security: "Legitimate use in mailing lists. In phishing, may reveal the actual sending infrastructure.", example: "Sender: mailinglist@listserv.example.com" },
  { header: "X-Priority", description: "Email priority level (1=High, 3=Normal, 5=Low).", security: "High priority (1) is commonly used in phishing to create urgency.", example: "X-Priority: 1" },
  { header: "Importance", description: "Message importance (high, normal, low).", security: "Similar to X-Priority; high importance in unexpected emails is a phishing indicator.", example: "Importance: high" },
  { header: "X-Auto-Response-Suppress", description: "Suppresses automatic responses (out-of-office, delivery receipts).", security: "Indicates the sender expects automated responses might be triggered; common in mass mailing.", example: "X-Auto-Response-Suppress: OOF, DR, RN, NRN" },
  { header: "Disposition-Notification-To", description: "Requests a read receipt.", security: "Phishing emails request read receipts to confirm the email was opened and the address is active.", example: "Disposition-Notification-To: sender@example.com" },
  { header: "X-Confirm-Reading-To", description: "Non-standard read receipt request (Lotus Notes, older clients).", security: "Same concern as Disposition-Notification-To.", example: "X-Confirm-Reading-To: sender@example.com" },
  { header: "In-Reply-To", description: "Message-ID of the email this is replying to.", security: "Thread hijacking: attacker replies to a legitimate conversation with a phishing email. Verify the In-Reply-To chain.", example: "In-Reply-To: <original-message-id@example.com>" },
  { header: "References", description: "Chain of Message-IDs in the conversation thread.", security: "Long reference chains in unexpected emails may indicate conversation thread hijacking (e.g., Emotet).", example: "References: <msg1@example.com> <msg2@example.com>" },
  { header: "X-Attached", description: "Lists attached filenames (non-standard, added by some servers).", security: "Quick check for suspicious attachment names (.exe, .scr, .js, .vbs, double extensions).", example: "X-Attached: invoice.pdf.exe" },
  { header: "Content-Disposition", description: "Specifies how to display the body part (inline or attachment) and filename.", security: "Check attachment filenames for malicious extensions. Double extensions (file.pdf.exe) are a classic trick.", example: "Content-Disposition: attachment; filename=\"report.docx\"" },
  { header: "X-PHP-Script", description: "PHP script that generated the email (added by some PHP mail functions).", security: "Reveals the server path of the sending script. Indicates webmail form or compromised web application sending spam.", example: "X-PHP-Script: /var/www/html/contact.php for 203.0.113.50" },
  { header: "X-Source", description: "Source of the email (added by some hosting providers).", security: "Reveals the hosting account or script that sent the email.", example: "X-Source: /usr/sbin/sendmail" },
  { header: "X-SES-Outgoing", description: "Amazon SES outgoing header.", security: "Confirms the email was sent via Amazon Simple Email Service. Legitimate for transactional email; suspicious if impersonating a company that doesn't use AWS.", example: "X-SES-Outgoing: 2024.01.01-93.184.216.34" },
  { header: "Feedback-ID", description: "Google/Gmail feedback loop identifier.", security: "Used by bulk senders for complaint tracking. Structure: campaign:sender:department:tenant.", example: "Feedback-ID: 12345:67890:campaign:example.com" },
  { header: "X-Mailgun-Sid", description: "Mailgun sending identifier.", security: "Confirms email sent via Mailgun service.", example: "X-Mailgun-Sid: WyIxMjM0NSIsICJ..." },
  { header: "X-PM-Message-Id", description: "Postmark message identifier.", security: "Confirms email sent via Postmark service.", example: "X-PM-Message-Id: abc123-def456" },
  { header: "X-Report-Abuse", description: "Link to report the email as abuse.", security: "Legitimate services include abuse reporting links.", example: "X-Report-Abuse: Please report abuse at https://example.com/abuse" },
];

export const SPF_REFERENCE = {
  version: "v=spf1",
  mechanisms: [
    { mechanism: "all", syntax: "+all / -all / ~all / ?all", description: "Matches everything. Used as the last mechanism.", security: "+all passes everything (NEVER use). -all fails everything not previously matched (recommended). ~all softfails (use during testing). ?all is neutral (provides no protection).", examples: ["v=spf1 include:_spf.google.com -all", "v=spf1 mx ~all"] },
    { mechanism: "include", syntax: "include:domain.com", description: "Recursively evaluates the SPF record of the specified domain.", security: "Each include counts as a DNS lookup (max 10 total). Deeply nested includes can exceed the limit, causing permerror.", examples: ["v=spf1 include:_spf.google.com include:sendgrid.net -all", "v=spf1 include:spf.protection.outlook.com -all"] },
    { mechanism: "a", syntax: "a / a:domain.com / a:domain.com/24", description: "Matches if the sender's IP matches an A/AAAA record of the domain.", security: "Useful for small deployments where the web server also sends email.", examples: ["v=spf1 a -all", "v=spf1 a:mail.example.com -all"] },
    { mechanism: "mx", syntax: "mx / mx:domain.com / mx:domain.com/24", description: "Matches if the sender's IP matches an MX record's A record.", security: "Allows your mail servers to send email. Each MX lookup counts toward the 10-lookup limit.", examples: ["v=spf1 mx -all", "v=spf1 mx:example.com -all"] },
    { mechanism: "ip4", syntax: "ip4:192.168.1.0/24 / ip4:10.0.0.1", description: "Matches a specific IPv4 address or CIDR range.", security: "Does NOT count as a DNS lookup. Best practice for explicitly listing sending IPs. Use instead of 'a' or 'include' when possible to reduce lookups.", examples: ["v=spf1 ip4:93.184.216.34 ip4:198.51.100.0/24 -all"] },
    { mechanism: "ip6", syntax: "ip6:2001:db8::/32 / ip6:2001:db8::1", description: "Matches a specific IPv6 address or prefix.", security: "Same as ip4 — no DNS lookup cost. Always include ip6 if your servers have IPv6.", examples: ["v=spf1 ip4:93.184.216.34 ip6:2001:db8::1 -all"] },
    { mechanism: "exists", syntax: "exists:%{i}.spf.example.com", description: "Passes if the specified domain has an A record. Used with macros for per-IP checks.", security: "Powerful but complex. Used by large senders for dynamic SPF (check if sender IP has a specific DNS entry). Counts as a DNS lookup.", examples: ["v=spf1 exists:%{i}._spf.example.com -all"] },
    { mechanism: "ptr", syntax: "ptr / ptr:domain.com", description: "Matches if the sender's IP reverse-resolves to a name under the domain. DEPRECATED.", security: "RFC 7208 says SHOULD NOT be used: slow (requires reverse DNS lookups), unreliable, and expensive. Many receivers ignore it.", examples: ["(deprecated — do not use)"] },
    { mechanism: "redirect", syntax: "redirect=_spf.example.com", description: "Replaces the current SPF record with the one at the specified domain. Used instead of include when the domain has no mechanisms of its own.", security: "Not a mechanism but a modifier. Only evaluated if no mechanisms match. Does not count as a separate DNS lookup beyond the redirect itself.", examples: ["v=spf1 redirect=_spf.example.com"] },
    { mechanism: "exp", syntax: "exp=explain._spf.example.com", description: "Custom explanation string returned on SPF fail. Points to a TXT record with the message.", security: "Purely informational — provides a human-readable explanation for why an email failed SPF.", examples: ["v=spf1 mx -all exp=spf-explain.example.com"] }
  ],
  qualifiers: [
    { qualifier: "+", name: "pass", description: "Default. The IP is authorized to send." },
    { qualifier: "-", name: "fail", description: "The IP is NOT authorized. Reject the email." },
    { qualifier: "~", name: "softfail", description: "The IP is probably not authorized. Accept but mark (often goes to spam)." },
    { qualifier: "?", name: "neutral", description: "No assertion about the IP. Treated as if no SPF exists." }
  ],
  common_records: [
    { provider: "Google Workspace", record: "v=spf1 include:_spf.google.com -all" },
    { provider: "Microsoft 365", record: "v=spf1 include:spf.protection.outlook.com -all" },
    { provider: "Amazon SES", record: "v=spf1 include:amazonses.com -all" },
    { provider: "SendGrid", record: "v=spf1 include:sendgrid.net -all" },
    { provider: "Mailchimp", record: "v=spf1 include:servers.mcsv.net -all" },
    { provider: "Mailgun", record: "v=spf1 include:mailgun.org -all" },
    { provider: "Postmark", record: "v=spf1 include:spf.mtasv.net -all" },
    { provider: "Zoho Mail", record: "v=spf1 include:zoho.com -all" },
    { provider: "ProtonMail", record: "v=spf1 include:_spf.protonmail.ch -all" },
    { provider: "Fastmail", record: "v=spf1 include:spf.messagingengine.com -all" },
    { provider: "Google + Microsoft", record: "v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all" },
    { provider: "Google + SendGrid", record: "v=spf1 include:_spf.google.com include:sendgrid.net -all" }
  ],
  best_practices: [
    "Always end with -all (hard fail) in production",
    "Keep DNS lookup count under 10 (include, a, mx, exists, redirect each cost 1 lookup; ip4 and ip6 are free)",
    "Use ip4/ip6 instead of include when you know the exact sending IPs",
    "Flatten SPF records for complex setups (tools: dmarcian, SPF Surveyor)",
    "Test with ~all (softfail) first, then switch to -all after verifying legitimate mail passes",
    "Monitor DMARC aggregate reports (rua) to identify legitimate senders missing from SPF",
    "Don't use ptr mechanism (deprecated per RFC 7208)",
    "Publish SPF for all domains, even those that don't send email: v=spf1 -all"
  ]
};

export const DKIM_REFERENCE = {
  overview: "DKIM (DomainKeys Identified Mail) uses public-key cryptography to sign outgoing emails. The sender's mail server adds a DKIM-Signature header with a cryptographic signature over specified headers and the body. The receiver fetches the public key from DNS (selector._domainkey.domain TXT record) and verifies the signature.",
  signature_fields: [
    { tag: "v", name: "Version", value: "1", description: "DKIM version (always 1)" },
    { tag: "a", name: "Algorithm", value: "rsa-sha256 | ed25519-sha256", description: "Signing algorithm. rsa-sha256 is standard; ed25519-sha256 is newer and more efficient." },
    { tag: "d", name: "Domain", value: "example.com", description: "The signing domain. This is the domain claiming responsibility for the email." },
    { tag: "s", name: "Selector", value: "selector1", description: "Used to locate the public key in DNS: selector._domainkey.example.com" },
    { tag: "h", name: "Headers", value: "from:to:subject:date", description: "List of headers included in the signature. 'from' is required. Headers not listed can be modified without breaking the signature." },
    { tag: "b", name: "Signature", value: "base64...", description: "The actual cryptographic signature (base64-encoded)" },
    { tag: "bh", name: "Body Hash", value: "base64...", description: "Hash of the canonicalized body (base64-encoded)" },
    { tag: "c", name: "Canonicalization", value: "relaxed/relaxed", description: "Header/body canonicalization: simple (exact match) or relaxed (tolerates whitespace changes). relaxed/relaxed is recommended." },
    { tag: "t", name: "Timestamp", value: "1704067200", description: "Unix timestamp when the signature was created" },
    { tag: "x", name: "Expiration", value: "1704672000", description: "Unix timestamp when the signature expires (optional)" },
    { tag: "l", name: "Body Length", value: "1000", description: "Number of body bytes signed. If set, content after this length is unsigned and can be modified. AVOID using this — it enables body append attacks." },
    { tag: "q", name: "Query Method", value: "dns/txt", description: "Method to retrieve the public key (always dns/txt)" }
  ],
  dns_record: {
    location: "selector._domainkey.example.com TXT",
    fields: [
      { tag: "v", value: "DKIM1", description: "DKIM key record version" },
      { tag: "k", value: "rsa | ed25519", description: "Key type" },
      { tag: "p", value: "base64-public-key", description: "Public key (base64-encoded). Empty p= means the key has been revoked." },
      { tag: "t", value: "y | s", description: "Flags: y=testing mode (don't act on failures), s=strict (d= domain must exactly match From domain)" },
      { tag: "h", value: "sha256", description: "Acceptable hash algorithms" },
      { tag: "g", value: "*", description: "Granularity (deprecated)" },
      { tag: "n", value: "notes", description: "Human-readable notes" }
    ],
    example: "selector1._domainkey.example.com. 300 IN TXT \"v=DKIM1; k=rsa; p=MIIBIjANBgkqhk...\""
  },
  best_practices: [
    "Use RSA 2048-bit keys minimum (1024-bit is crackable); consider Ed25519 for new deployments",
    "Sign at least: from, to, subject, date, message-id, content-type, mime-version",
    "Use relaxed/relaxed canonicalization for better compatibility with forwarding",
    "Rotate keys every 6-12 months; use different selectors for each key generation",
    "Don't use the l= (body length) tag — it allows attackers to append content to signed emails",
    "Publish DKIM records for all selectors; remove old selectors by setting p= to empty (revocation)",
    "Monitor DMARC reports for DKIM alignment failures",
    "Use DKIM with both SPF and DMARC for maximum protection"
  ]
};

export const DMARC_REFERENCE = {
  overview: "DMARC (Domain-based Message Authentication, Reporting, and Conformance) builds on SPF and DKIM. It tells receiving mail servers what to do when an email fails authentication, and provides reporting back to the domain owner.",
  record_location: "_dmarc.example.com TXT",
  tags: [
    { tag: "v", required: true, values: ["DMARC1"], description: "Version (must be DMARC1)" },
    { tag: "p", required: true, values: ["none", "quarantine", "reject"], description: "Policy for the domain. none=monitor only, quarantine=send to spam, reject=block entirely." },
    { tag: "sp", required: false, values: ["none", "quarantine", "reject"], description: "Subdomain policy. If not set, inherits p= value." },
    { tag: "rua", required: false, values: ["mailto:dmarc@example.com"], description: "Aggregate report recipients (daily XML reports with authentication statistics)." },
    { tag: "ruf", required: false, values: ["mailto:forensics@example.com"], description: "Forensic (failure) report recipients (per-message reports for failed emails). Many providers don't send ruf reports due to privacy concerns." },
    { tag: "pct", required: false, values: ["0-100"], description: "Percentage of messages to apply the policy to. Useful for gradual rollout: start at pct=10, increase over time." },
    { tag: "adkim", required: false, values: ["r", "s"], description: "DKIM alignment mode. r=relaxed (subdomains OK), s=strict (exact domain match required)." },
    { tag: "aspf", required: false, values: ["r", "s"], description: "SPF alignment mode. r=relaxed (subdomains OK), s=strict (exact domain match)." },
    { tag: "fo", required: false, values: ["0", "1", "d", "s"], description: "Failure reporting options. 0=report if ALL fail, 1=report if ANY fail, d=DKIM failure, s=SPF failure." },
    { tag: "rf", required: false, values: ["afrf"], description: "Report format (Authentication Failure Reporting Format)." },
    { tag: "ri", required: false, values: ["86400"], description: "Reporting interval in seconds (default 86400 = daily)." }
  ],
  example_records: [
    { stage: "Monitoring", record: "v=DMARC1; p=none; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com; fo=1", description: "Start here. Monitor authentication results without affecting delivery." },
    { stage: "Quarantine (gradual)", record: "v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@example.com", description: "Quarantine 25% of failing emails. Increase pct over time." },
    { stage: "Quarantine (full)", record: "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com", description: "Quarantine all failing emails (send to spam folder)." },
    { stage: "Reject", record: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s", description: "Full protection. Reject all failing emails. Strict alignment for both DKIM and SPF." },
    { stage: "Non-sending domain", record: "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com", description: "For domains that should NEVER send email. Combined with SPF 'v=spf1 -all' and no MX records." }
  ],
  alignment: {
    description: "DMARC requires that SPF or DKIM 'aligns' with the From header domain. Alignment means the authenticated domain matches the From domain.",
    spf_alignment: "The Return-Path domain must match the From domain (relaxed: organizational domain match; strict: exact match)",
    dkim_alignment: "The DKIM d= domain must match the From domain (relaxed: organizational domain match; strict: exact match)",
    example: "From: user@example.com — SPF checks Return-Path domain, DKIM checks d= domain. If either aligns with example.com and passes, DMARC passes."
  }
};

export const BEC_PATTERNS = [
  { id: 1, name: "CEO Fraud / Executive Impersonation", description: "Attacker impersonates the CEO or C-suite executive, requesting urgent wire transfers to a vendor. Often targets finance department.", indicators: ["Urgency and secrecy (don't tell anyone)", "Request for wire transfer to new account", "Sent from lookalike domain or compromised executive email", "Claims to be traveling or in a meeting (can't talk on phone)", "Bypasses normal approval process"], example_subject: "URGENT - Wire Transfer Needed Today", estimated_loss: "$26 billion globally (2016-2019 per FBI)" },
  { id: 2, name: "Invoice Fraud / Vendor Impersonation", description: "Attacker impersonates a known vendor, sending a fake invoice with updated banking details. The payment goes to the attacker's account.", indicators: ["Invoice from known vendor with changed bank details", "Email from slightly different domain (vendor-inc.com vs vendor.com)", "Request to update payment information", "Urgency around overdue payment"], example_subject: "Updated Banking Information for Invoice #12345", estimated_loss: "$2.3 billion (2020 per FBI IC3)" },
  { id: 3, name: "Account Compromise", description: "Attacker compromises an actual employee's email account and uses it to send requests to contacts, vendors, or the finance team.", indicators: ["Legitimate email account sending unusual requests", "Inbox rules forwarding emails to external address", "Login from unusual location or IP", "Email sent outside normal working hours"], example_subject: "Re: Outstanding Payment", estimated_loss: "Varies — harder to detect due to legitimate account" },
  { id: 4, name: "Attorney/Legal Impersonation", description: "Attacker poses as a lawyer handling a confidential matter, pressuring the target to make immediate payment to avoid legal consequences.", indicators: ["Claims of confidential/sensitive legal matter", "Pressure not to discuss with others", "Urgent payment request", "References to lawsuits, audits, or regulatory action"], example_subject: "Confidential Legal Matter - Immediate Action Required", estimated_loss: "Significant — targets executives and finance" },
  { id: 5, name: "W-2 / Tax Form Phishing", description: "Attacker impersonates HR or an executive, requesting employee W-2 forms or tax information. Used for identity theft and tax fraud.", indicators: ["Request for all employee W-2s or tax forms", "Impersonates CEO or HR director", "Timed around tax season (January-April)", "Requests sent to payroll or HR staff"], example_subject: "2025 Employee W-2 Forms Needed", estimated_loss: "Identity theft affecting hundreds of employees per incident" },
  { id: 6, name: "Payroll Diversion", description: "Attacker impersonates an employee and requests a change to their direct deposit information, diverting salary payments.", indicators: ["Request to change direct deposit account", "Sent from personal email claiming work email is down", "New bank account details", "Request made just before pay period"], example_subject: "Please Update My Direct Deposit", estimated_loss: "Average $7,904 per incident (FBI)" },
  { id: 7, name: "Gift Card Scam", description: "Attacker impersonates a manager or executive, requesting purchase of gift cards for employees or clients. Asks for card numbers via email.", indicators: ["Request for iTunes, Amazon, or Google Play gift cards", "Claims surprise gift for employees or clients", "Asks to scratch off cards and send numbers via email", "Urgency — needed before end of day"], example_subject: "Quick Favor - Need Gift Cards", estimated_loss: "Usually $500-$5,000 per incident" },
  { id: 8, name: "Real Estate Wire Fraud", description: "Attacker compromises a real estate agent, title company, or buyer's email and sends fake closing instructions with attacker's bank details.", indicators: ["Last-minute change to wire instructions", "Email from compromised real estate professional", "Different account details than previously provided", "Urgency around closing date"], example_subject: "Updated Wire Transfer Instructions for Closing", estimated_loss: "Average $150,000+ per incident" },
  { id: 9, name: "Supply Chain Compromise", description: "Attacker compromises a vendor's email system and sends fraudulent invoices or requests to all of the vendor's customers.", indicators: ["Legitimate vendor email sending unusual payment requests", "Multiple customers targeted simultaneously", "Subtle changes to invoice details", "Vendor unaware of outgoing emails"], example_subject: "Invoice #8765 - Updated Payment Method", estimated_loss: "Can affect dozens of companies simultaneously" },
  { id: 10, name: "Merger/Acquisition Scam", description: "Attacker references a real or fake M&A deal, claiming urgent payment is needed to close. Targets executives involved in deals.", indicators: ["References confidential business deal", "Extreme urgency and secrecy", "Large payment request", "Impersonates external counsel or deal advisor"], example_subject: "Acquisition Closing - Urgent Wire Required", estimated_loss: "Can exceed $1 million per incident" },
];

export const EMAIL_FORENSICS_CHECKLIST = [
  { step: 1, action: "Extract full email headers", description: "View the raw email source (Show Original in Gmail, View Source in Outlook). Copy all headers for analysis.", tools: ["Gmail: Show Original", "Outlook: View Message Source", "mxtoolbox.com/EmailHeaders.aspx"] },
  { step: 2, action: "Trace the Received chain", description: "Read Received headers bottom-to-top. Each hop adds a Received header. The bottom one is closest to the origin. Check for IP consistency and server names.", tools: ["Google Admin Toolbox", "MXToolbox Header Analyzer"] },
  { step: 3, action: "Verify authentication results", description: "Check Authentication-Results header for SPF, DKIM, and DMARC pass/fail. A legitimate email from a major provider should pass all three.", tools: ["Manual header inspection"] },
  { step: 4, action: "Compare From and Return-Path", description: "If the From address domain differs from the Return-Path domain, investigate why. Legitimate cases: mailing lists, SaaS transactional email. Suspicious: unrelated domains.", tools: ["Manual comparison"] },
  { step: 5, action: "Check DKIM signing domain", description: "The DKIM d= domain should match or be related to the From domain. A DKIM signature from sendgrid.net for a bank email is legitimate (outsourced sending). A signature from random-domain.xyz is not.", tools: ["Manual inspection of DKIM-Signature header"] },
  { step: 6, action: "Analyze originating IP", description: "Find the originating IP from X-Originating-IP header or the first Received header. Look up the IP: geolocation, ASN, reputation, blacklist status.", tools: ["whois", "ipinfo.io", "abuseipdb.com", "mxtoolbox.com/blacklists.aspx", "virustotal.com"] },
  { step: 7, action: "Examine X-Mailer and User-Agent", description: "Check what email client was used. A spoofed corporate email claiming to be from Outlook but sent by a PHP script (X-PHP-Script) is suspicious.", tools: ["Manual header inspection"] },
  { step: 8, action: "Inspect URLs in the body", description: "Hover over links (don't click). Check for: lookalike domains, URL shorteners, data URIs, JavaScript in URLs, encoded characters, redirects.", tools: ["urlscan.io", "VirusTotal URL scan", "any.run"] },
  { step: 9, action: "Analyze attachments", description: "Check file types, sizes, and names. Look for double extensions (.pdf.exe), macro-enabled Office files (.docm, .xlsm), archives containing executables. Scan with multiple AV engines.", tools: ["VirusTotal", "Hybrid Analysis", "any.run", "Joe Sandbox", "olevba (for Office macros)"] },
  { step: 10, action: "Check for known indicators", description: "Search IOC databases for sender IP, domain, URLs, and file hashes found in the email.", tools: ["VirusTotal", "OTX (AlienVault)", "ThreatFox", "PhishTank", "URLhaus"] },
  { step: 11, action: "Document and report", description: "Record all findings: headers, IPs, domains, URLs, file hashes, authentication results. Report to security team and submit phishing samples.", tools: ["Incident tracking system", "abuse@provider.com", "phishing@irs.gov (for tax scams)", "ic3.gov (FBI)"] },
];

export const EMAIL_ENCRYPTION = {
  pgp: {
    name: "PGP / GPG (Pretty Good Privacy / GNU Privacy Guard)",
    model: "Web of Trust — users sign each other's keys to establish trust",
    key_types: ["RSA (2048-4096 bit)", "Ed25519/Curve25519", "ECDSA/ECDH (NIST curves)"],
    operation: "Sender encrypts with recipient's public key + signs with sender's private key. Recipient decrypts with their private key + verifies signature with sender's public key.",
    standards: ["OpenPGP (RFC 4880)", "PGP/MIME (RFC 3156)", "Crypto Refresh (RFC 9580)"],
    tools: ["GnuPG (gpg)", "Kleopatra", "Enigmail (Thunderbird)", "Mailvelope (webmail)", "ProtonMail (built-in)", "Tutanota"],
    limitations: ["Headers (including Subject) are NOT encrypted by default", "Key management is complex for non-technical users", "Web of Trust is difficult to bootstrap", "No forward secrecy — compromised private key decrypts all past messages"]
  },
  smime: {
    name: "S/MIME (Secure/Multipurpose Internet Mail Extensions)",
    model: "Certificate Authority — trust is established through X.509 certificate hierarchy",
    key_types: ["RSA (2048-4096 bit)", "ECDSA (P-256, P-384)"],
    operation: "Similar to PGP but uses X.509 certificates from CAs instead of PGP keys. Built into most enterprise email clients.",
    standards: ["S/MIME v4 (RFC 8551)", "S/MIME v3.2 (RFC 5751)"],
    tools: ["Outlook (built-in)", "Apple Mail (built-in)", "Thunderbird", "Evolution"],
    limitations: ["Requires certificates from a CA (cost for organization-validated certs)", "Certificate management overhead", "No forward secrecy", "Interoperability issues between different S/MIME implementations"]
  }
};
