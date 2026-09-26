// Phishing email analysis and awareness tool
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const SHORTENERS = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","rebrand.ly","bl.ink","short.io","cutt.ly","lnkd.in","rb.gy","v.gd","qr.ae","adf.ly","shorte.st","ouo.io","bc.vc","s.id"];
const DANGEROUS_EXTS = [".exe",".scr",".bat",".cmd",".ps1",".vbs",".vbe",".js",".jse",".wsf",".wsh",".msi",".msp",".com",".pif",".hta",".cpl",".inf",".reg",".rgs",".sct",".shb",".iso",".img",".vhd",".vhdx",".cab",".dll",".ocx",".sys",".lnk",".url",".application",".gadget",".jar",".docm",".xlsm",".pptm",".dotm",".xltm",".potm",".sldm",".ppam",".xlam"];
const BRANDS = ["paypal","amazon","apple","microsoft","google","facebook","instagram","netflix","bank of america","chase","wells fargo","citibank","usps","fedex","ups","dhl","irs","social security","dropbox","linkedin","twitter","spotify","adobe","zoom","docusign","walmart","target","costco","bestbuy","ebay","coinbase","binance","metamask","steam","blizzard","riot"];
const URGENCY_WORDS = ["act now","immediately","urgent","expire","suspended","verify your","confirm your","unusual activity","unauthorized","limited time","within 24 hours","click here","update your payment","confirm your identity","your account will be","failure to","last warning","final notice","security alert","important update","action required","response required"];
const HOMOGLYPHS = {"a":"аàáâãä","e":"еèéêë","i":"іìíîï","o":"оòóôõöο","u":"ùúûü","c":"сç","n":"ñ","p":"р","s":"ş","y":"уý","l":"ӏ","d":"ԁ","g":"ɡ","h":"һ","k":"к","m":"м","t":"т","w":"ѡ","x":"х"};

function parseHeaders(raw) {
  const headers = {};
  const received = [];
  const lines = raw.split(/\r?\n/);
  let current = "";
  for (let i = 0; i < lines.length; i++) {
    if (/^\s/.test(lines[i]) && current) {
      current += " " + lines[i].trim();
    } else {
      if (current) {
        const idx = current.indexOf(":");
        if (idx > 0) {
          const key = current.slice(0, idx).trim().toLowerCase();
          const val = current.slice(idx + 1).trim();
          if (key === "received") received.push(val);
          else headers[key] = val;
        }
      }
      current = lines[i];
    }
  }
  if (current) {
    const idx = current.indexOf(":");
    if (idx > 0) {
      const key = current.slice(0, idx).trim().toLowerCase();
      const val = current.slice(idx + 1).trim();
      if (key === "received") received.push(val);
      else headers[key] = val;
    }
  }
  headers._received = received;
  return headers;
}

function extractEmails(text) {
  return (text.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || []).filter((v, i, a) => a.indexOf(v) === i);
}
function extractURLs(text) {
  return (text.match(/https?:\/\/[^\s<>"')\]]+/gi) || []).filter((v, i, a) => a.indexOf(v) === i);
}
function extractIPs(text) {
  return (text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter((v, i, a) => a.indexOf(v) === i);
}
function extractDomains(text) {
  return (text.match(/(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}/g) || []).filter((v, i, a) => a.indexOf(v) === i);
}
function extractHashes(text) {
  const md5 = text.match(/\b[a-fA-F0-9]{32}\b/g) || [];
  const sha1 = text.match(/\b[a-fA-F0-9]{40}\b/g) || [];
  const sha256 = text.match(/\b[a-fA-F0-9]{64}\b/g) || [];
  return { md5: md5.filter((v,i,a) => a.indexOf(v)===i), sha1: sha1.filter((v,i,a) => a.indexOf(v)===i), sha256: sha256.filter((v,i,a) => a.indexOf(v)===i) };
}

function defangURL(url) {
  return url.replace(/https?/i, function(m) { return m.replace(/t/g, "x"); }).replace(/\./g, "[.]");
}
function defangIP(ip) { return ip.replace(/\./g, "[.]"); }
function defangEmail(em) { return em.replace("@", "[@]").replace(/\./g, "[.]"); }

function analyzeForPhishing(headers, body) {
  const flags = [];
  const lowerBody = (body || "").toLowerCase();
  const from = headers["from"] || "";
  const replyTo = headers["reply-to"] || "";
  const returnPath = headers["return-path"] || "";
  const subject = headers["subject"] || "";
  const received = headers._received || [];

  // From / Reply-To mismatch
  if (replyTo && from) {
    const fromDomain = (from.match(/@([a-zA-Z0-9.\-]+)/)||[])[1];
    const replyDomain = (replyTo.match(/@([a-zA-Z0-9.\-]+)/)||[])[1];
    if (fromDomain && replyDomain && fromDomain.toLowerCase() !== replyDomain.toLowerCase()) {
      flags.push({ severity: "high", msg: "From domain (" + esc(fromDomain) + ") does not match Reply-To domain (" + esc(replyDomain) + ")" });
    }
  }
  // Return-Path mismatch
  if (returnPath && from) {
    const fromDomain = (from.match(/@([a-zA-Z0-9.\-]+)/)||[])[1];
    const rpDomain = (returnPath.match(/@([a-zA-Z0-9.\-]+)/)||[])[1];
    if (fromDomain && rpDomain && fromDomain.toLowerCase() !== rpDomain.toLowerCase()) {
      flags.push({ severity: "medium", msg: "From domain does not match Return-Path domain (" + esc(rpDomain) + ")" });
    }
  }
  // Display name spoofing
  const displayNameMatch = from.match(/^"?([^"<]+)"?\s*</);
  if (displayNameMatch) {
    const displayName = displayNameMatch[1].trim().toLowerCase();
    const fromEmail = (from.match(/<([^>]+)>/)||[])[1] || "";
    if (fromEmail && displayName.includes("@") && !fromEmail.toLowerCase().includes(displayName.split("@")[1])) {
      flags.push({ severity: "high", msg: "Display name contains an email address that differs from the actual sender" });
    }
  }
  // SPF checks
  const spf = [headers["authentication-results"], headers["received-spf"]].filter(Boolean).join(" ");
  if (/spf=fail/i.test(spf)) flags.push({ severity: "critical", msg: "SPF authentication failed" });
  else if (/spf=softfail/i.test(spf)) flags.push({ severity: "high", msg: "SPF authentication softfail" });
  else if (/spf=none/i.test(spf)) flags.push({ severity: "medium", msg: "No SPF record found for sender domain" });
  // DKIM checks
  if (/dkim=fail/i.test(spf)) flags.push({ severity: "critical", msg: "DKIM signature verification failed" });
  else if (!(/dkim=pass/i.test(spf)) && spf) flags.push({ severity: "medium", msg: "DKIM signature not present or not verified" });
  // DMARC checks
  if (/dmarc=fail/i.test(spf)) flags.push({ severity: "critical", msg: "DMARC authentication failed" });
  else if (/dmarc=none/i.test(spf)) flags.push({ severity: "medium", msg: "No DMARC policy found for sender domain" });
  // Urgency language
  var urgencyFound = [];
  URGENCY_WORDS.forEach(function(w) { if (lowerBody.includes(w) || subject.toLowerCase().includes(w)) urgencyFound.push(w); });
  if (urgencyFound.length > 0) flags.push({ severity: urgencyFound.length > 3 ? "high" : "medium", msg: "Urgency language detected: " + urgencyFound.map(esc).join(", ") });
  // Suspicious URLs
  var urls = extractURLs(body || "");
  urls.forEach(function(u) {
    try {
      var urlObj = new URL(u);
      // IP-based URL
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(urlObj.hostname)) {
        flags.push({ severity: "high", msg: "URL uses IP address instead of domain: " + esc(defangURL(u.slice(0,80))) });
      }
      // URL shortener
      if (SHORTENERS.some(function(s) { return urlObj.hostname.toLowerCase() === s; })) {
        flags.push({ severity: "medium", msg: "URL shortener detected: " + esc(defangURL(u.slice(0,80))) });
      }
      // Lookalike domain
      var host = urlObj.hostname.toLowerCase();
      BRANDS.forEach(function(b) {
        var clean = b.replace(/\s+/g, "");
        if (host.includes(clean) && !host.endsWith("." + clean + ".com") && !host.endsWith("." + clean + ".org") && host !== clean + ".com") {
          flags.push({ severity: "high", msg: "Possible brand impersonation in URL: " + esc(b) + " in " + esc(defangURL(urlObj.hostname)) });
        }
      });
      // Encoded characters
      if (/%[0-9a-f]{2}/i.test(urlObj.pathname) && /%2f|%5c|%2e/i.test(urlObj.pathname)) {
        flags.push({ severity: "medium", msg: "URL contains suspicious encoded characters: " + esc(defangURL(u.slice(0,80))) });
      }
    } catch(e) {}
  });
  // Dangerous attachments
  var attachments = (body || "").match(/filename="?([^"\s;]+)"?/gi) || [];
  var headerAttachments = (headers["content-disposition"] || "").match(/filename="?([^"\s;]+)"?/gi) || [];
  attachments = attachments.concat(headerAttachments);
  attachments.forEach(function(a) {
    var fname = a.replace(/filename="?/i, "").replace(/"$/, "").toLowerCase();
    DANGEROUS_EXTS.forEach(function(ext) {
      if (fname.endsWith(ext)) {
        flags.push({ severity: "critical", msg: "Dangerous attachment type: " + esc(fname) + " (" + esc(ext) + ")" });
      }
    });
    // Double extension
    var parts = fname.split(".");
    if (parts.length > 2) {
      var lastExt = "." + parts[parts.length - 1];
      if (DANGEROUS_EXTS.includes(lastExt)) {
        flags.push({ severity: "critical", msg: "Double extension detected (social engineering): " + esc(fname) });
      }
    }
  });
  // Brand impersonation in From/Subject
  var fromLower = from.toLowerCase();
  var subjLower = subject.toLowerCase();
  BRANDS.forEach(function(b) {
    if ((fromLower.includes(b) || subjLower.includes(b)) && !(fromLower.includes("@" + b.replace(/\s+/g,"") + "."))) {
      flags.push({ severity: "medium", msg: "Brand name '" + esc(b) + "' appears in email but sender is not from official domain" });
    }
  });
  // Received chain anomalies
  if (received.length > 7) {
    flags.push({ severity: "low", msg: "Unusually long Received chain (" + received.length + " hops) may indicate relaying" });
  }
  // HTML form in body
  if (/<form/i.test(body || "")) {
    flags.push({ severity: "high", msg: "Email contains an HTML form (possible credential harvesting)" });
  }
  // Base64 encoded links
  if (/href="data:/i.test(body || "")) {
    flags.push({ severity: "high", msg: "Email contains data: URI links (obfuscation technique)" });
  }
  // JavaScript in email
  if (/<script/i.test(body || "")) {
    flags.push({ severity: "critical", msg: "Email contains JavaScript (potential malicious code)" });
  }
  // Hidden text
  if (/display:\s*none|visibility:\s*hidden|font-size:\s*0/i.test(body || "")) {
    flags.push({ severity: "medium", msg: "Email contains hidden text (possible anti-spam evasion)" });
  }
  // Homoglyph detection in from domain
  var fromDomainFull = (from.match(/@([a-zA-Z0-9.\-]+)/)||[])[1] || "";
  if (fromDomainFull) {
    var hasHomoglyph = false;
    for (var ci = 0; ci < fromDomainFull.length; ci++) {
      var ch = fromDomainFull[ci];
      for (var hk in HOMOGLYPHS) {
        if (HOMOGLYPHS[hk].includes(ch)) { hasHomoglyph = true; break; }
      }
      if (hasHomoglyph) break;
    }
    if (hasHomoglyph) flags.push({ severity: "critical", msg: "Homoglyph characters detected in sender domain (IDN homograph attack)" });
  }
  // No flags is good
  if (flags.length === 0) flags.push({ severity: "info", msg: "No obvious phishing indicators detected. Always verify with the sender through a known channel." });

  return flags;
}

const QUIZ = [
  { email: "From: security@paypa1.com\nSubject: Your account has been limited\n\nDear Customer,\nWe have noticed unusual activity on your account. Please verify your identity immediately by clicking the link below or your account will be permanently suspended within 24 hours.\n\nhttp://paypa1-secure.com/verify?id=38291", isPhishing: true, explanation: "The domain is paypa1.com (number 1 instead of letter l). Multiple urgency phrases, threatening permanent suspension, IP-based redirect likely." },
  { email: "From: noreply@github.com\nSubject: [GitHub] A new sign-in to your account\n\nHey username,\nA new sign-in was detected for your GitHub account.\nDevice: Chrome on Windows\nLocation: San Francisco, CA\nIP: 203.0.113.42\n\nIf this was you, no further action is needed. If not, please review your security settings:\nhttps://github.com/settings/security", isPhishing: false, explanation: "Legitimate GitHub notification. Official domain, no urgency language, link goes to github.com, informational tone, doesn't ask for credentials." },
  { email: "From: Apple Support <support@apple.com.verify-id.net>\nSubject: Your Apple ID was used to sign in to iCloud\n\nYour Apple ID was used to sign in to iCloud via a web browser.\nDate: March 15, 2026\nBrowser: Chrome\nOS: Windows\n\nIf this wasn't you, click here immediately to secure your account:\nhttps://apple.com.verify-id.net/secure", isPhishing: true, explanation: "The actual domain is verify-id.net, not apple.com. The display shows apple.com but it's a subdomain of a different domain. Classic subdomain spoofing technique." },
  { email: "From: HR Department <hr@company.com>\nSubject: Updated Employee Handbook - Action Required\n\nAll employees,\nPlease review the updated employee handbook attached. You must acknowledge receipt by end of week.\n\nAttachment: Employee_Handbook_2026.pdf", isPhishing: false, explanation: "Internal company email with a PDF attachment. No urgency pressure, legitimate request, normal business communication. However, always verify unexpected attachments." },
  { email: "From: Amazon <no-reply@arnazon.com>\nSubject: Order Confirmation #402-8891742\n\nThank you for your order!\nOrder Total: $1,847.99\nShipping: 2-day\n\nIf you did not place this order, click here immediately to cancel:\nhttps://arnazon.com/cancel-order", isPhishing: true, explanation: "Domain is arnazon.com (rn looks like m). High dollar amount to create panic. Urgency to click cancel link. Classic lookalike domain attack." },
  { email: "From: Microsoft 365 <admin@microsoft.com>\nSubject: Password Expiration Notice\n\nYour password will expire in 2 days. Please update your password at:\nhttps://login.microsoftonline.com/common/oauth2/authorize\n\nIT Department", isPhishing: false, explanation: "Uses official Microsoft domain (microsoftonline.com is legitimate). However, organizations should verify these via their IT department directly. Password expiry emails can be legitimate but are also commonly spoofed." },
  { email: "From: Netflix <billing@netflix-payment.com>\nSubject: Payment Failed - Update Your Information\n\nWe were unable to process your payment. Your account will be suspended unless you update your billing information within 48 hours.\n\nUpdate Payment: https://netflix-payment.com/update", isPhishing: true, explanation: "Domain is netflix-payment.com, not netflix.com. Urgency (48 hours), threatening suspension. Netflix sends billing emails from netflix.com only." },
  { email: "From: DocuSign <dse@docusign.net>\nSubject: Please sign: NDA Agreement\n\nJohn Smith sent you a document to review and sign.\nDocument: Non-Disclosure Agreement\n\nREVIEW DOCUMENT\nhttps://app.docusign.com/documents/abc123", isPhishing: false, explanation: "DocuSign uses docusign.net for transactional emails and app.docusign.com for document links. This matches their legitimate sending pattern. Still, verify with the sender if unexpected." },
  { email: "From: IT Support <helpdesk@company.com>\nSubject: Urgent: Email Storage Full\n\nYour mailbox is 98% full. Click below to increase your storage or your email will stop receiving messages:\n\nhttps://mail-upgrade.company-portal.com/storage?user=jsmith\n\nIT Help Desk", isPhishing: true, explanation: "While it appears internal, the link goes to company-portal.com (external domain), not company.com. Storage full scams are common phishing tactics. Real IT would use internal systems." },
  { email: "From: LinkedIn <messages-noreply@linkedin.com>\nSubject: You have 3 new connection requests\n\nHi Professional,\nYou have pending invitations:\n- John Smith, CEO at TechCorp\n- Jane Doe, Recruiter at BigCo\n- Bob Wilson, VP Sales at StartupXYZ\n\nView invitations: https://www.linkedin.com/comm/mynetwork/", isPhishing: false, explanation: "Legitimate LinkedIn notification format. Uses linkedin.com domain for both sender and links. Standard connection request notification." },
];

const AUTH_EXPLAINER = [
  { name: "SPF (Sender Policy Framework)", desc: "SPF allows domain owners to specify which mail servers are authorized to send email on their behalf. The receiving server checks the sending IP against the domain's SPF DNS record (TXT). Results: pass (authorized), fail (not authorized), softfail (not authorized but not strict), neutral, none (no record).", flow: "Sender -> Receiving MTA checks: Is sending IP in sender-domain's SPF TXT record? -> pass/fail/softfail" },
  { name: "DKIM (DomainKeys Identified Mail)", desc: "DKIM uses public-key cryptography to sign email headers and body. The sending server signs the message with a private key, and the receiving server verifies it using the public key published in DNS. This ensures the message wasn't tampered with in transit.", flow: "Sender signs message with private key -> Adds DKIM-Signature header -> Receiver fetches public key from DNS (selector._domainkey.domain) -> Verifies signature" },
  { name: "DMARC (Domain-based Message Authentication, Reporting & Conformance)", desc: "DMARC builds on SPF and DKIM. It tells receiving servers what to do when SPF/DKIM fail (none: monitor, quarantine: spam folder, reject: drop). It also requires alignment: the From domain must match the SPF/DKIM domain. DMARC reports are sent to the domain owner for visibility.", flow: "Receiver checks SPF and DKIM -> Checks DMARC alignment (From domain matches?) -> Applies DMARC policy (none/quarantine/reject) -> Sends aggregate/forensic reports to domain owner" },
  { name: "ARC (Authenticated Received Chain)", desc: "ARC preserves email authentication results across intermediaries (mailing lists, forwarding). When a message is forwarded, SPF/DKIM may break. ARC allows intermediaries to attest to the authentication results they observed, creating a chain of custody.", flow: "Original sender (SPF/DKIM pass) -> Mailing list forwards (breaks SPF) -> ARC seals original results -> Receiver trusts ARC chain" },
  { name: "BIMI (Brand Indicators for Message Identification)", desc: "BIMI allows brands to display their logo next to authenticated emails in supporting mail clients. Requires DMARC enforcement (quarantine/reject policy) and a Verified Mark Certificate (VMC). The logo is specified via a DNS TXT record at default._bimi.domain.", flow: "Domain has DMARC enforcement + BIMI DNS record + VMC certificate -> Email passes DMARC -> Mail client displays brand logo" },
];

const PHISHING_KIT_INDICATORS = [
  "Login page with no other navigation or links",
  "URL contains keywords like 'login', 'verify', 'secure', 'update', 'confirm' combined with brand names",
  "SSL certificate is free/Let's Encrypt on a suspicious domain",
  "Page source contains references to PHP mailers or credential harvesting scripts",
  "Form action posts to a different domain or IP address",
  "Page was recently registered (check WHOIS)",
  "Multiple redirects before reaching the final page",
  "Page looks identical to legitimate site but URL is different",
  "Missing or incorrect favicon",
  "Console shows JavaScript errors from hastily copied code",
  "Form fields capture more info than needed (SSN on a 'login' page)",
  "Page disappears shortly after campaign is reported",
  "robots.txt blocks all crawlers to avoid detection",
  "Directory listing is enabled showing kit files (.zip, .tar.gz)",
  "Uses iframes to load legitimate site content around the phishing form",
];

function renderHeaderAnalysisTab(container) {
  container.innerHTML =
    '<h2 class="pg-h2">Email Header Analyzer</h2>' +
    '<p class="muted">Paste the full email headers below. The parser will extract key fields and trace the email\'s delivery path.</p>' +
    '<textarea class="tk-in" id="pa-headers" rows="12" placeholder="Paste raw email headers here...\n\nExample:\nFrom: sender@example.com\nTo: recipient@example.com\nSubject: Test\nDate: Mon, 1 Jan 2026 12:00:00 +0000\nReceived: from mail.example.com (1.2.3.4) by mx.recipient.com\nAuthentication-Results: mx.recipient.com; spf=pass; dkim=pass; dmarc=pass"></textarea>' +
    '<div class="tk-btns"><button class="btn sm" id="pa-parse-headers">Parse Headers</button></div>' +
    '<pre class="tk-out" id="pa-headers-out"></pre>';

  container.querySelector("#pa-parse-headers").onclick = function() {
    var raw = container.querySelector("#pa-headers").value.trim();
    if (!raw) { container.querySelector("#pa-headers-out").textContent = "Paste email headers above."; return; }
    var h = parseHeaders(raw);
    var out = "=== PARSED EMAIL HEADERS ===\n\n";
    var fields = [["From", h["from"]], ["To", h["to"]], ["Subject", h["subject"]], ["Date", h["date"]], ["Reply-To", h["reply-to"]], ["Return-Path", h["return-path"]], ["Message-ID", h["message-id"]], ["X-Mailer", h["x-mailer"]], ["Content-Type", h["content-type"]], ["MIME-Version", h["mime-version"]]];
    fields.forEach(function(f) { if (f[1]) out += f[0] + ": " + f[1] + "\n"; });
    out += "\n=== AUTHENTICATION RESULTS ===\n";
    var authRes = h["authentication-results"] || h["received-spf"] || "Not found";
    out += authRes + "\n";
    if (h._received.length) {
      out += "\n=== RECEIVED CHAIN (newest first) ===\n";
      h._received.forEach(function(r, i) { out += "\nHop " + (i+1) + ": " + r + "\n"; });
    }
    container.querySelector("#pa-headers-out").textContent = out;
  };
}

function renderRedFlagTab(container) {
  container.innerHTML =
    '<h2 class="pg-h2">Phishing Red Flag Detector</h2>' +
    '<p class="muted">Paste the full email (headers + body) below. The analyzer checks 30+ phishing indicators.</p>' +
    '<textarea class="tk-in" id="pa-redflag-input" rows="12" placeholder="Paste the complete email (headers and body) here..."></textarea>' +
    '<div class="tk-btns"><button class="btn sm" id="pa-redflag-analyze">Analyze</button></div>' +
    '<div id="pa-redflag-out"></div>';

  container.querySelector("#pa-redflag-analyze").onclick = function() {
    var raw = container.querySelector("#pa-redflag-input").value.trim();
    if (!raw) return;
    var headerEnd = raw.indexOf("\n\n");
    var headerPart = headerEnd > 0 ? raw.slice(0, headerEnd) : raw;
    var bodyPart = headerEnd > 0 ? raw.slice(headerEnd + 2) : "";
    var h = parseHeaders(headerPart);
    var flags = analyzeForPhishing(h, bodyPart || raw);
    var severityColors = { critical: "#ef4444", high: "#f97316", medium: "#f59e0b", low: "#3b82f6", info: "#22c55e" };
    var html = '<div style="margin-top:12px">';
    html += '<div style="font-size:1.1rem;font-weight:600;margin-bottom:8px">Analysis Results: ' + flags.length + ' finding(s)</div>';
    flags.forEach(function(f) {
      html += '<div style="display:flex;gap:8px;align-items:flex-start;padding:8px 12px;margin:4px 0;border-left:3px solid ' + (severityColors[f.severity] || "#888") + ';background:var(--card);border-radius:0 4px 4px 0">';
      html += '<span style="font-size:.7rem;font-weight:700;text-transform:uppercase;min-width:60px;color:' + (severityColors[f.severity] || "#888") + '">' + esc(f.severity) + '</span>';
      html += '<span style="font-size:.85rem">' + f.msg + '</span>';
      html += '</div>';
    });
    html += '</div>';
    container.querySelector("#pa-redflag-out").innerHTML = html;
  };
}

function renderDefangerTab(container) {
  container.innerHTML =
    '<h2 class="pg-h2">IOC Defanger / Refanger</h2>' +
    '<p class="muted">Convert URLs, IPs, and email addresses to safe (defanged) format for sharing in reports, or refang them back.</p>' +
    '<textarea class="tk-in" id="pa-defang-input" rows="6" placeholder="Paste URLs, IPs, or emails here...\nhttps://malicious.example.com\n192.168.1.1\nuser@malware.com"></textarea>' +
    '<div class="tk-btns">' +
      '<button class="btn sm" id="pa-defang">Defang</button>' +
      '<button class="btn sm" id="pa-refang">Refang</button>' +
    '</div>' +
    '<pre class="tk-out" id="pa-defang-out"></pre>';

  container.querySelector("#pa-defang").onclick = function() {
    var input = container.querySelector("#pa-defang-input").value;
    var result = input;
    result = result.replace(/https?:\/\/[^\s]+/gi, function(u) { return defangURL(u); });
    result = result.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, function(m) { return defangIP(m); });
    result = result.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, function(m) { return defangEmail(m); });
    container.querySelector("#pa-defang-out").textContent = result;
  };
  container.querySelector("#pa-refang").onclick = function() {
    var input = container.querySelector("#pa-defang-input").value;
    var result = input.replace(/hxxp/gi, "http").replace(/\[\.\]/g, ".").replace(/\[@\]/g, "@");
    container.querySelector("#pa-defang-out").textContent = result;
  };
}

function renderIOCTab(container) {
  container.innerHTML =
    '<h2 class="pg-h2">IOC Extractor</h2>' +
    '<p class="muted">Extract all indicators of compromise (IPs, domains, URLs, emails, hashes) from email text.</p>' +
    '<textarea class="tk-in" id="pa-ioc-input" rows="10" placeholder="Paste email content here..."></textarea>' +
    '<div class="tk-btns"><button class="btn sm" id="pa-ioc-extract">Extract IOCs</button><button class="btn sm" id="pa-ioc-copy">Copy All</button></div>' +
    '<pre class="tk-out" id="pa-ioc-out"></pre>';

  container.querySelector("#pa-ioc-extract").onclick = function() {
    var text = container.querySelector("#pa-ioc-input").value;
    var ips = extractIPs(text);
    var urls = extractURLs(text);
    var emails = extractEmails(text);
    var domains = extractDomains(text);
    var hashes = extractHashes(text);
    var out = "=== EXTRACTED IOCs ===\n\n";
    if (ips.length) out += "--- IP Addresses (" + ips.length + ") ---\n" + ips.map(defangIP).join("\n") + "\n\n";
    if (urls.length) out += "--- URLs (" + urls.length + ") ---\n" + urls.map(defangURL).join("\n") + "\n\n";
    if (emails.length) out += "--- Email Addresses (" + emails.length + ") ---\n" + emails.map(defangEmail).join("\n") + "\n\n";
    if (domains.length) out += "--- Domains (" + domains.length + ") ---\n" + domains.join("\n") + "\n\n";
    if (hashes.md5.length) out += "--- MD5 Hashes (" + hashes.md5.length + ") ---\n" + hashes.md5.join("\n") + "\n\n";
    if (hashes.sha1.length) out += "--- SHA-1 Hashes (" + hashes.sha1.length + ") ---\n" + hashes.sha1.join("\n") + "\n\n";
    if (hashes.sha256.length) out += "--- SHA-256 Hashes (" + hashes.sha256.length + ") ---\n" + hashes.sha256.join("\n") + "\n\n";
    if (!ips.length && !urls.length && !emails.length && !hashes.md5.length) out += "No IOCs found in the provided text.\n";
    container.querySelector("#pa-ioc-out").textContent = out;
  };
  container.querySelector("#pa-ioc-copy").onclick = function() {
    var text = container.querySelector("#pa-ioc-out").textContent;
    if (text) { navigator.clipboard.writeText(text).catch(function(){}); }
  };
}

function renderQuizTab(container) {
  var currentQ = 0;
  var score = 0;
  var answered = false;

  function renderQuestion() {
    var q = QUIZ[currentQ];
    var html = '<h2 class="pg-h2">Phishing Awareness Quiz</h2>' +
      '<p class="muted">Question ' + (currentQ + 1) + ' of ' + QUIZ.length + ' | Score: ' + score + '/' + currentQ + '</p>' +
      '<div style="background:var(--card);border:1px solid var(--line);padding:16px;border-radius:6px;margin:12px 0;white-space:pre-wrap;font-family:var(--font-mono,monospace);font-size:.82rem;line-height:1.6">' + esc(q.email) + '</div>' +
      '<p style="font-weight:600;margin:12px 0">Is this email phishing or legitimate?</p>' +
      '<div class="tk-btns" id="pa-quiz-btns">' +
        '<button class="btn sm" id="pa-quiz-phishing" style="min-width:120px">Phishing</button>' +
        '<button class="btn sm ghost" id="pa-quiz-legit" style="min-width:120px">Legitimate</button>' +
      '</div>' +
      '<div id="pa-quiz-feedback" style="margin-top:12px"></div>';
    container.innerHTML = html;
    answered = false;

    container.querySelector("#pa-quiz-phishing").onclick = function() { answer(true); };
    container.querySelector("#pa-quiz-legit").onclick = function() { answer(false); };
  }

  function answer(guessedPhishing) {
    if (answered) return;
    answered = true;
    var q = QUIZ[currentQ];
    var correct = guessedPhishing === q.isPhishing;
    if (correct) score++;
    var fb = container.querySelector("#pa-quiz-feedback");
    fb.innerHTML =
      '<div style="padding:12px;border-radius:6px;border:1px solid ' + (correct ? "var(--acc)" : "#ef4444") + ';background:' + (correct ? "rgba(0,212,255,0.08)" : "rgba(239,68,68,0.08)") + '">' +
        '<div style="font-weight:600;margin-bottom:4px">' + (correct ? "Correct!" : "Incorrect") + ' This email is ' + (q.isPhishing ? "PHISHING" : "LEGITIMATE") + '.</div>' +
        '<div style="font-size:.85rem;color:var(--mut)">' + esc(q.explanation) + '</div>' +
      '</div>' +
      (currentQ < QUIZ.length - 1
        ? '<div class="tk-btns" style="margin-top:8px"><button class="btn sm" id="pa-quiz-next">Next Question</button></div>'
        : '<div style="margin-top:12px;font-weight:600">Quiz complete! Final score: ' + score + '/' + QUIZ.length + '</div>');
    if (currentQ < QUIZ.length - 1) {
      container.querySelector("#pa-quiz-next").onclick = function() { currentQ++; renderQuestion(); };
    }
  }

  renderQuestion();
}

function renderReportTab(container) {
  container.innerHTML =
    '<h2 class="pg-h2">Phishing Report Generator</h2>' +
    '<p class="muted">Fill in the details below to generate a formatted phishing incident report.</p>' +
    '<div style="display:grid;gap:8px;max-width:600px">' +
      '<label style="font-size:.8rem;font-weight:500">Reporter Name<input class="tk-f" id="pa-rpt-name" placeholder="Your name"></label>' +
      '<label style="font-size:.8rem;font-weight:500">Date Received<input class="tk-f" id="pa-rpt-date" type="date"></label>' +
      '<label style="font-size:.8rem;font-weight:500">Sender Email<input class="tk-f" id="pa-rpt-sender" placeholder="phisher@evil.com"></label>' +
      '<label style="font-size:.8rem;font-weight:500">Subject Line<input class="tk-f" id="pa-rpt-subject" placeholder="Email subject"></label>' +
      '<label style="font-size:.8rem;font-weight:500">Suspicious URLs (one per line)<textarea class="tk-in" id="pa-rpt-urls" rows="3" placeholder="https://evil.com/login"></textarea></label>' +
      '<label style="font-size:.8rem;font-weight:500">Actions Taken<textarea class="tk-in" id="pa-rpt-actions" rows="3" placeholder="Did not click links. Reported to IT. Deleted email."></textarea></label>' +
      '<label style="font-size:.8rem;font-weight:500">Additional Notes<textarea class="tk-in" id="pa-rpt-notes" rows="3" placeholder="Any other observations..."></textarea></label>' +
    '</div>' +
    '<div class="tk-btns"><button class="btn sm" id="pa-rpt-gen">Generate Report</button><button class="btn sm" id="pa-rpt-copy">Copy Report</button></div>' +
    '<pre class="tk-out" id="pa-rpt-out"></pre>';

  container.querySelector("#pa-rpt-gen").onclick = function() {
    var name = container.querySelector("#pa-rpt-name").value || "N/A";
    var date = container.querySelector("#pa-rpt-date").value || new Date().toISOString().slice(0,10);
    var sender = container.querySelector("#pa-rpt-sender").value || "N/A";
    var subject = container.querySelector("#pa-rpt-subject").value || "N/A";
    var urls = container.querySelector("#pa-rpt-urls").value || "None identified";
    var actions = container.querySelector("#pa-rpt-actions").value || "N/A";
    var notes = container.querySelector("#pa-rpt-notes").value || "None";
    var report = "========================================\n" +
      "    PHISHING INCIDENT REPORT\n" +
      "========================================\n\n" +
      "Date: " + date + "\n" +
      "Reported by: " + name + "\n" +
      "Status: Under Investigation\n\n" +
      "--- SUSPECT EMAIL DETAILS ---\n" +
      "Sender: " + sender + "\n" +
      "Subject: " + subject + "\n\n" +
      "--- SUSPICIOUS URLs ---\n" +
      urls.split("\n").map(function(u) { return u.trim() ? "  " + defangURL(u.trim()) : ""; }).filter(Boolean).join("\n") + "\n\n" +
      "--- ACTIONS TAKEN ---\n" + actions + "\n\n" +
      "--- ADDITIONAL NOTES ---\n" + notes + "\n\n" +
      "--- RECOMMENDATIONS ---\n" +
      "1. Block sender domain at email gateway\n" +
      "2. Add suspicious URLs to blocklist\n" +
      "3. Search mailbox logs for other recipients\n" +
      "4. Alert affected users if any clicked links\n" +
      "5. Reset credentials if any were entered\n" +
      "6. Preserve email as evidence (EML format)\n\n" +
      "========================================\n" +
      "Generated by Darknode Phishing Analyzer\n" +
      "========================================\n";
    container.querySelector("#pa-rpt-out").textContent = report;
  };
  container.querySelector("#pa-rpt-copy").onclick = function() {
    navigator.clipboard.writeText(container.querySelector("#pa-rpt-out").textContent).catch(function(){});
  };
}

function renderAuthExplainerTab(container) {
  var html = '<h2 class="pg-h2">Email Authentication Explained</h2>' +
    '<p class="muted">How SPF, DKIM, DMARC, ARC, and BIMI protect against email spoofing and phishing.</p>';
  AUTH_EXPLAINER.forEach(function(auth) {
    html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;margin:10px 0">' +
      '<h3 style="margin:0 0 6px;font-size:.95rem;color:var(--acc)">' + esc(auth.name) + '</h3>' +
      '<p style="font-size:.85rem;line-height:1.6;margin:0 0 8px">' + esc(auth.desc) + '</p>' +
      '<div style="background:var(--card2,#111);border-radius:4px;padding:10px;font-family:var(--font-mono,monospace);font-size:.78rem;color:var(--acc)">' + esc(auth.flow) + '</div>' +
    '</div>';
  });
  container.innerHTML = html;
}

function renderPhishingKitTab(container) {
  var html = '<h2 class="pg-h2">Phishing Kit Detection</h2>' +
    '<p class="muted">Common characteristics of phishing pages and kits that help identify them during investigations.</p>' +
    '<div style="margin-top:12px">';
  PHISHING_KIT_INDICATORS.forEach(function(ind, i) {
    html += '<div style="display:flex;gap:8px;align-items:flex-start;padding:8px 12px;border-left:2px solid var(--acc);margin:4px 0;font-size:.85rem">' +
      '<span style="color:var(--acc);font-weight:600;min-width:20px">' + (i+1) + '.</span>' +
      '<span>' + esc(ind) + '</span>' +
    '</div>';
  });
  html += '</div>';
  container.innerHTML = html;
}

function renderURLAnalyzerTab(container) {
  container.innerHTML =
    '<h2 class="pg-h2">URL Analyzer</h2>' +
    '<p class="muted">Paste URLs to analyze their structure, identify suspicious patterns, and check against known indicators.</p>' +
    '<textarea class="tk-in" id="pa-url-input" rows="4" placeholder="https://suspicious-site.com/login?redirect=https://evil.com"></textarea>' +
    '<div class="tk-btns"><button class="btn sm" id="pa-url-analyze">Analyze URLs</button></div>' +
    '<div id="pa-url-out"></div>';

  container.querySelector("#pa-url-analyze").onclick = function() {
    var input = container.querySelector("#pa-url-input").value;
    var urls = extractURLs(input);
    if (!urls.length) { container.querySelector("#pa-url-out").innerHTML = '<p class="muted">No URLs found.</p>'; return; }
    var html = '';
    urls.forEach(function(u) {
      try {
        var urlObj = new URL(u);
        var warnings = [];
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(urlObj.hostname)) warnings.push("Uses IP address instead of domain name");
        if (SHORTENERS.some(function(s) { return urlObj.hostname.toLowerCase() === s; })) warnings.push("URL shortener detected");
        if (urlObj.hostname.split(".").length > 4) warnings.push("Excessive subdomains (possible subdomain spoofing)");
        if (urlObj.port && !["80","443"].includes(urlObj.port)) warnings.push("Non-standard port: " + urlObj.port);
        if (urlObj.username || urlObj.password) warnings.push("Credentials embedded in URL (basic auth bypass technique)");
        if (/%[0-9a-f]{2}/i.test(urlObj.pathname)) warnings.push("URL-encoded characters in path");
        if (urlObj.search && /password|passwd|token|key|secret|auth/i.test(urlObj.search)) warnings.push("Sensitive parameter names in query string");
        var tld = urlObj.hostname.split(".").pop();
        if (["tk","ml","ga","cf","gq","buzz","xyz","top","work","click","link","info","online","site","website","space","fun","icu","monster"].includes(tld)) warnings.push("Suspicious TLD: ." + tld);

        html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px;margin:8px 0">' +
          '<div style="font-family:var(--font-mono,monospace);font-size:.8rem;word-break:break-all;margin-bottom:8px;color:var(--acc)">' + esc(defangURL(u)) + '</div>' +
          '<div style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:.82rem">' +
            '<span class="muted">Protocol:</span><span>' + esc(urlObj.protocol) + '</span>' +
            '<span class="muted">Hostname:</span><span>' + esc(urlObj.hostname) + '</span>' +
            '<span class="muted">Port:</span><span>' + esc(urlObj.port || "default") + '</span>' +
            '<span class="muted">Path:</span><span>' + esc(urlObj.pathname) + '</span>' +
            '<span class="muted">Query:</span><span>' + esc(urlObj.search || "none") + '</span>' +
            '<span class="muted">Fragment:</span><span>' + esc(urlObj.hash || "none") + '</span>' +
            '<span class="muted">TLD:</span><span>' + esc(tld) + '</span>' +
          '</div>';
        if (warnings.length) {
          html += '<div style="margin-top:8px;border-top:1px solid var(--line);padding-top:8px">';
          warnings.forEach(function(w) {
            html += '<div style="font-size:.8rem;color:#f59e0b;padding:2px 0">[!] ' + esc(w) + '</div>';
          });
          html += '</div>';
        }
        html += '</div>';
      } catch(e) {
        html += '<div style="color:#ef4444;font-size:.85rem">Invalid URL: ' + esc(u.slice(0,100)) + '</div>';
      }
    });
    container.querySelector("#pa-url-out").innerHTML = html;
  };
}

const PA_TABS = [
  { id: "headers", label: "Header Analyzer", render: renderHeaderAnalysisTab },
  { id: "redflags", label: "Red Flag Detector", render: renderRedFlagTab },
  { id: "defang", label: "Defanger", render: renderDefangerTab },
  { id: "urls", label: "URL Analyzer", render: renderURLAnalyzerTab },
  { id: "ioc", label: "IOC Extractor", render: renderIOCTab },
  { id: "quiz", label: "Phishing Quiz", render: renderQuizTab },
  { id: "report", label: "Report Generator", render: renderReportTab },
  { id: "auth", label: "Auth Explainer", render: renderAuthExplainerTab },
  { id: "kits", label: "Kit Detection", render: renderPhishingKitTab },
];

export function renderPhishingAnalyzer(main) {
  main.innerHTML =
    '<h1 class="pg-h1">Phishing Analyzer</h1>' +
    '<p class="muted pg-sub">Analyze suspicious emails, detect phishing indicators, extract IOCs, and train awareness.</p>' +
    '<div class="tab-bar" id="pa-tabs">' +
      PA_TABS.map(function(t, i) { return '<button class="tab' + (i === 0 ? ' active' : '') + '" data-tab="' + t.id + '">' + t.label + '</button>'; }).join('') +
    '</div>' +
    '<div id="pa-content" style="margin-top:12px"></div>';

  var tabBar = main.querySelector('#pa-tabs');
  var content = main.querySelector('#pa-content');

  function switchTab(tabId) {
    tabBar.querySelectorAll('.tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === tabId); });
    var tab = PA_TABS.find(function(t) { return t.id === tabId; });
    if (tab) { content.innerHTML = ''; tab.render(content); }
  }
  tabBar.onclick = function(e) {
    var btn = e.target.closest('.tab');
    if (btn) switchTab(btn.dataset.tab);
  };
  switchTab('headers');
}
