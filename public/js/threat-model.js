// threat-model.js
// darknode.ai -- Threat Modeling Workbench
//
// Interactive threat modeling suite covering STRIDE, DREAD, PASTA, LINDDUN,
// attack tree construction, data flow diagram reference, a large threat
// library, asset inventory, risk matrix generation, security requirements
// generation, compliance mapping (NIST 800-53 / ISO 27001 / CIS Controls),
// and a consolidated report generator.
//
// Vanilla JS, no frameworks. Dark cyberpunk theme classes are provided by
// the site stylesheet (btn, card, panel, pg-h1, pg-h2, muted, pg-sub, tk-in,
// tk-out, tk-btns, tk-row, tk-f, mono, stat, stat-n, stat-l, dl-cmd,
// cmd-block, tab-bar, tab, qa, qa-title, qa-desc, eyebrow).

/* ============================================================================
   SECTION 0: SMALL UTILITIES
   ========================================================================== */

function tmEsc(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function tmUid(prefix) {
  return `${prefix || 'id'}-${Math.random().toString(36).slice(2, 9)}-${Date.now().toString(36)}`;
}

function tmClamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function tmClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

function tmDownload(filename, text) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function tmCopyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => {});
  } else {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) { /* noop */ }
    document.body.removeChild(ta);
  }
}

function tmFormatDate(d) {
  const dt = d ? new Date(d) : new Date();
  const yyyy = dt.getFullYear();
  const mm = String(dt.getMonth() + 1).padStart(2, '0');
  const dd = String(dt.getDate()).padStart(2, '0');
  const hh = String(dt.getHours()).padStart(2, '0');
  const mi = String(dt.getMinutes()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}`;
}

function tmSeverityColor(sev) {
  const s = String(sev || '').toLowerCase();
  if (s === 'critical') return '#ff2e63';
  if (s === 'high') return '#ff5f56';
  if (s === 'medium') return '#ffbd2e';
  if (s === 'low') return '#27c93f';
  return '#8b98a5';
}

function tmEl(tag, attrs, children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const k of Object.keys(attrs)) {
      if (k === 'class') el.className = attrs[k];
      else if (k === 'html') el.innerHTML = attrs[k];
      else if (k.startsWith('on') && typeof attrs[k] === 'function') {
        el.addEventListener(k.slice(2).toLowerCase(), attrs[k]);
      } else {
        el.setAttribute(k, attrs[k]);
      }
    }
  }
  if (children) {
    for (const c of [].concat(children)) {
      if (typeof c === 'string') el.appendChild(document.createTextNode(c));
      else if (c) el.appendChild(c);
    }
  }
  return el;
}

/* ============================================================================
   SECTION 1: STRIDE DATA
   ========================================================================== */

const STRIDE_CATEGORIES = [
  {
    key: 'spoofing',
    letter: 'S',
    name: 'Spoofing',
    tagline: 'Pretending to be something or someone other than yourself',
    violates: 'Authentication',
    description:
      'Spoofing threats involve an attacker impersonating a person, process, device, or system component to gain unauthorized access or trust. Spoofing attacks target the authentication guarantees of a system: they succeed whenever an attacker can convince a component that a forged identity claim is genuine. Spoofing can occur at any trust boundary -- a user logging in, a service calling another service, a device joining a network, or a message claiming to originate from a trusted sender.',
    examples: [
      'An attacker uses a phished username and password to log in as a legitimate employee.',
      'A rogue access point broadcasts the SSID of a corporate Wi-Fi network to capture credentials.',
      'An email is sent with a forged "From" header to impersonate a company executive (CEO fraud).',
      'A service account token is stolen and replayed to call an internal microservice.',
      'An attacker spoofs the source IP address of packets to bypass IP allow-lists.',
      'A malicious mobile app mimics the UI of a legitimate banking app to harvest credentials.',
      'DNS cache poisoning redirects users to an attacker-controlled server that looks identical to the real one.',
      'A forged JWT is presented with a manipulated "sub" claim after the signature check is skipped.',
    ],
    mitigations: [
      'Require strong, phishing-resistant multi-factor authentication (FIDO2/WebAuthn) for all privileged accounts.',
      'Use mutual TLS (mTLS) for service-to-service authentication rather than shared secrets.',
      'Validate every authentication token signature, issuer, audience, and expiry on every request.',
      'Implement SPF, DKIM, and DMARC to reduce email spoofing and header forgery.',
      'Bind sessions to device fingerprints or client certificates where feasible.',
      'Use short-lived credentials and automatic credential rotation for machine identities.',
      'Enforce certificate pinning in mobile and desktop clients that talk to a known backend.',
      'Log and alert on authentication from anomalous geolocations, ASNs, or impossible travel patterns.',
      'Disable legacy authentication protocols (NTLM, basic auth) that do not support MFA.',
      'Adopt a zero-trust model that re-verifies identity at every hop instead of trusting the network perimeter.',
    ],
    questions: [
      { id: 'sp-q1', question: 'Can an attacker authenticate as another user without knowing that user\'s credentials?', guidance: 'Check for default credentials, predictable session tokens, and authentication bypass logic paths.' },
      { id: 'sp-q2', question: 'Are passwords, API keys, or tokens transmitted or stored without adequate protection?', guidance: 'Verify TLS everywhere and that secrets are hashed or encrypted at rest, never logged in plaintext.' },
      { id: 'sp-q3', question: 'Can session tokens or cookies be predicted, brute-forced, or replayed after logout?', guidance: 'Use cryptographically random session identifiers and invalidate them server-side on logout.' },
      { id: 'sp-q4', question: 'Is multi-factor authentication enforced for administrative and privileged accounts?', guidance: 'Confirm MFA cannot be bypassed via legacy endpoints, password-reset flows, or "remember me" abuse.' },
      { id: 'sp-q5', question: 'Can a service impersonate another internal service when calling shared APIs?', guidance: 'Check for mutual TLS or signed service tokens rather than implicit network trust.' },
      { id: 'sp-q6', question: 'Are email or messaging channels protected against sender-address forgery?', guidance: 'Verify SPF, DKIM, and DMARC are configured and enforced, not just monitored.' },
      { id: 'sp-q7', question: 'Can DNS responses be poisoned or spoofed to redirect clients to a malicious endpoint?', guidance: 'Check for DNSSEC validation and pinned resolvers on critical infrastructure.' },
      { id: 'sp-q8', question: 'Is device or endpoint identity verified before granting network or VPN access?', guidance: 'Look for certificate-based device authentication versus shared PSKs.' },
      { id: 'sp-q9', question: 'Can an attacker forge or reuse a JWT, SAML assertion, or OAuth token?', guidance: 'Confirm signature verification, audience checks, and expiry enforcement on every consumer.' },
      { id: 'sp-q10', question: 'Are password-reset and account-recovery flows resistant to impersonation?', guidance: 'Check for weak security questions, predictable reset tokens, or lack of out-of-band confirmation.' },
      { id: 'sp-q11', question: 'Can an attacker clone or replay biometric or hardware-token authentication?', guidance: 'Verify liveness detection and challenge-response mechanisms rather than static templates.' },
      { id: 'sp-q12', question: 'Is there protection against IP address or MAC address spoofing on internal networks?', guidance: 'Check for 802.1X, DHCP snooping, and dynamic ARP inspection on switches.' },
      { id: 'sp-q13', question: 'Can a malicious app or website impersonate the look-and-feel of a trusted client?', guidance: 'Consider code-signing, app-store verification, and user education against look-alike domains.' },
      { id: 'sp-q14', question: 'Are third-party or partner integrations authenticated with unique, revocable credentials?', guidance: 'Avoid shared API keys across partners; use per-partner credentials with scoped permissions.' },
      { id: 'sp-q15', question: 'Can an attacker bypass single sign-on by targeting a weaker legacy authentication path?', guidance: 'Inventory every login entry point and confirm none skip the central identity provider.' },
      { id: 'sp-q16', question: 'Is mutual authentication used for IoT or embedded devices connecting to backend services?', guidance: 'Check for unique per-device certificates rather than a single shared factory secret.' },
      { id: 'sp-q17', question: 'Can an attacker perform a man-in-the-middle attack to intercept and relay authentication material?', guidance: 'Verify certificate validation is not disabled and HSTS is enforced.' },
      { id: 'sp-q18', question: 'Are API keys embedded in client-side code, mobile binaries, or public repositories?', guidance: 'Search source and build artifacts for hard-coded secrets; rotate any that are exposed.' },
    ],
  },
  {
    key: 'tampering',
    letter: 'T',
    name: 'Tampering',
    tagline: 'Modifying data or code without authorization',
    violates: 'Integrity',
    description:
      'Tampering threats involve the unauthorized modification of data, code, or configuration -- whether in transit, at rest, or during processing. Tampering breaks the integrity guarantee of a system: consumers of the data can no longer trust that what they see reflects what was actually produced or intended. Tampering can target application data, system binaries, configuration files, log records, or the communication channels between components.',
    examples: [
      'An attacker modifies a price parameter in an HTTP request before it reaches the server.',
      'A supply-chain attacker injects malicious code into a widely used open-source package.',
      'An insider modifies audit logs to hide evidence of unauthorized access.',
      'A man-in-the-middle attacker alters a software update package before installation.',
      'SQL injection is used to modify records directly in the database.',
      'An attacker tampers with a mobile app\'s local storage to unlock premium features without payment.',
      'A firmware update is intercepted and replaced with a backdoored image.',
      'Configuration drift allows an attacker to disable security controls unnoticed.',
    ],
    mitigations: [
      'Sign all software artifacts, containers, and firmware images, and verify signatures before execution.',
      'Use parameterized queries or ORM layers to prevent injection-based data tampering.',
      'Protect data in transit with TLS 1.2+ and enforce certificate validation on all clients.',
      'Implement write-once, append-only, or hash-chained audit logs shipped to a separate trust domain.',
      'Apply integrity checks (HMAC, checksums) to critical configuration and data files.',
      'Use infrastructure-as-code with drift detection to catch unauthorized configuration changes.',
      'Adopt software bill of materials (SBOM) and dependency pinning to reduce supply-chain tampering.',
      'Enforce least privilege on write access to production data stores and code repositories.',
      'Require signed commits and mandatory code review before merging to protected branches.',
      'Use file integrity monitoring (FIM) on critical system binaries and configuration paths.',
    ],
    questions: [
      { id: 'ta-q1', question: 'Can client-side parameters (price, quantity, role) be modified before submission?', guidance: 'Ensure the server re-validates and re-derives all security-relevant values, never trusting client input.' },
      { id: 'ta-q2', question: 'Are database queries built through string concatenation vulnerable to injection?', guidance: 'Audit for parameterized queries, prepared statements, and ORM escaping everywhere user input flows.' },
      { id: 'ta-q3', question: 'Is data integrity verified when received from external partners or third-party APIs?', guidance: 'Check for checksums, signatures, or schema validation on inbound data.' },
      { id: 'ta-q4', question: 'Can an attacker modify software update packages in transit or at rest?', guidance: 'Confirm update packages are code-signed and signatures are verified before installation.' },
      { id: 'ta-q5', question: 'Are audit logs protected from modification or deletion by the accounts they monitor?', guidance: 'Ship logs to an append-only, separately privileged system immediately upon generation.' },
      { id: 'ta-q6', question: 'Can dependency or package repositories be poisoned with malicious versions?', guidance: 'Use lockfiles, checksum verification, and a vetted internal package mirror.' },
      { id: 'ta-q7', question: 'Is there protection against unauthorized changes to production configuration?', guidance: 'Require change control, IaC pull requests, and drift detection alerts.' },
      { id: 'ta-q8', question: 'Can request or message integrity be violated in transit between services?', guidance: 'Use TLS with certificate validation and consider message-level signing for high-value transactions.' },
      { id: 'ta-q9', question: 'Are file uploads validated against tampering with content-type or embedded metadata?', guidance: 'Re-encode or sanitize uploads server-side and verify actual content type, not just extension.' },
      { id: 'ta-q10', question: 'Can source code repositories accept unsigned or unreviewed commits to protected branches?', guidance: 'Enforce branch protection, required reviews, and commit signing.' },
      { id: 'ta-q11', question: 'Is firmware or embedded device code protected against unauthorized reflashing?', guidance: 'Use secure boot and signed firmware images validated by hardware root of trust.' },
      { id: 'ta-q12', question: 'Can cached or offline data be tampered with while the device is disconnected?', guidance: 'Apply integrity checks when reloading cached data and re-validate on reconnect.' },
      { id: 'ta-q13', question: 'Are API request bodies protected against parameter pollution or type confusion?', guidance: 'Use strict schema validation that rejects unexpected fields or duplicate parameters.' },
      { id: 'ta-q14', question: 'Can backup files be modified to reintroduce a compromised state upon restore?', guidance: 'Verify backup integrity hashes and store backups in immutable, access-controlled storage.' },
      { id: 'ta-q15', question: 'Is there a mechanism to detect unauthorized modification of critical system binaries?', guidance: 'Deploy file integrity monitoring with alerting on unexpected hash changes.' },
      { id: 'ta-q16', question: 'Can an attacker tamper with client-side JavaScript to bypass validation logic?', guidance: 'Never rely on client-side validation alone; always re-enforce rules server-side.' },
      { id: 'ta-q17', question: 'Are container images scanned and signed before deployment to production?', guidance: 'Use image signing (e.g., cosign) and admission controllers that reject unsigned images.' },
      { id: 'ta-q18', question: 'Can webhook payloads be forged or replayed without signature verification?', guidance: 'Verify HMAC signatures and timestamps on every inbound webhook before processing.' },
    ],
  },
  {
    key: 'repudiation',
    letter: 'R',
    name: 'Repudiation',
    tagline: 'Denying having performed an action without a way to prove otherwise',
    violates: 'Non-repudiation',
    description:
      'Repudiation threats occur when a user or system can deny having performed an action, and there is insufficient evidence to prove otherwise. This weakens accountability: without reliable, tamper-resistant records of who did what and when, organizations cannot investigate incidents, satisfy audit requirements, or hold malicious insiders accountable. Repudiation is closely linked to tampering (attackers may destroy evidence) and to weak authentication (shared accounts make it impossible to attribute actions to an individual).',
    examples: [
      'A user deletes a purchase order and denies ever placing it because no audit trail exists.',
      'An administrator shares a root account among the whole team, making individual actions unattributable.',
      'Logs are stored only locally and are wiped by the attacker after a breach.',
      'A financial transaction is disputed and there is no cryptographic proof of authorization.',
      'An employee claims they never approved a change, and the change-management system has no signature.',
      'Application logs record only "user performed action" without a verifiable session or request ID.',
      'A support engineer accesses customer data through an internal tool that keeps no access log.',
      'An attacker uses a stolen session to perform actions and the victim later denies performing them, complicating incident response.',
    ],
    mitigations: [
      'Implement centralized, tamper-evident logging (write-once storage, hash chaining, or a SIEM with restricted write access).',
      'Attribute every privileged action to a unique, individually authenticated identity -- eliminate shared accounts.',
      'Use digital signatures for high-value transactions and approvals to create non-repudiable proof.',
      'Timestamp and correlate logs across services using synchronized clocks (NTP) and trace IDs.',
      'Retain logs for a duration that satisfies legal, regulatory, and forensic requirements.',
      'Send logs off-host in near real time so a compromised system cannot erase its own history.',
      'Require step-up authentication (re-auth or MFA) before highly sensitive or destructive actions.',
      'Implement transaction receipts or confirmation emails that create an independent evidence trail.',
      'Enable database-level audit logging in addition to application-level logging for defense in depth.',
      'Use blockchain-inspired hash chaining or trusted timestamping services for legally significant records.',
    ],
    questions: [
      { id: 're-q1', question: 'Does the system log who performed each security-relevant action, with a timestamp?', guidance: 'Check that logs capture user identity, action, target resource, and result -- not just "something happened".' },
      { id: 're-q2', question: 'Are logs protected from deletion or modification by the very users they record?', guidance: 'Verify write-once storage or forwarding to a separate system the user cannot access.' },
      { id: 're-q3', question: 'Are shared or generic accounts used for administrative access?', guidance: 'Eliminate shared root/admin accounts in favor of individually attributable credentials plus privilege elevation.' },
      { id: 're-q4', question: 'Can a user deny having submitted a transaction due to lack of cryptographic proof?', guidance: 'Consider digital signatures or MFA-backed confirmation for high-value actions.' },
      { id: 're-q5', question: 'Are system clocks synchronized so log timestamps can be reliably correlated?', guidance: 'Confirm NTP is enforced across all hosts and time drift is monitored.' },
      { id: 're-q6', question: 'Is there sufficient log retention to support forensic investigation after an incident?', guidance: 'Check retention periods against legal, contractual, and regulatory obligations.' },
      { id: 're-q7', question: 'Are API calls traceable back to the originating client, session, and user?', guidance: 'Ensure trace IDs and authenticated context propagate through every downstream call.' },
      { id: 're-q8', question: 'Can log forwarding be disabled or intercepted by a compromised host before reaching the SIEM?', guidance: 'Use push-based, authenticated log shipping and alert on gaps in expected log volume.' },
      { id: 're-q9', question: 'Are approval workflows recorded with an identifiable approver and justification?', guidance: 'Verify change-management and approval systems store signer identity, not just a checkbox.' },
      { id: 're-q10', question: 'Is customer-facing evidence (receipts, confirmations) generated independently of the user\'s own client?', guidance: 'Server-generated, emailed confirmations create evidence the user cannot unilaterally alter.' },
      { id: 're-q11', question: 'Can database records be altered directly, bypassing the application\'s audit logging?', guidance: 'Enable database-native audit logging as a secondary control independent of the app layer.' },
      { id: 're-q12', question: 'Are privileged sessions recorded (keystroke or session recording) for sensitive systems?', guidance: 'Consider session recording for jump hosts and break-glass administrative access.' },
      { id: 're-q13', question: 'Is there a documented chain of custody for evidence collected during incident response?', guidance: 'Verify forensic procedures capture who collected evidence, when, and how it was preserved.' },
      { id: 're-q14', question: 'Can log integrity be independently verified, e.g., via hash chaining or checksums?', guidance: 'Use append-only log structures with periodic integrity digests published externally.' },
      { id: 're-q15', question: 'Are non-repudiation requirements defined for legally or financially significant transactions?', guidance: 'Identify which transactions need signatures versus standard audit logging.' },
    ],
  },
  {
    key: 'information_disclosure',
    letter: 'I',
    name: 'Information Disclosure',
    tagline: 'Exposing information to individuals not authorized to see it',
    violates: 'Confidentiality',
    description:
      'Information disclosure threats involve the exposure of data to parties who are not authorized to access it. This violates confidentiality and can affect data in transit, at rest, in use, or even indirectly through side channels such as error messages, timing differences, or metadata. Information disclosure ranges from large-scale data breaches to subtle leaks like verbose error pages, unprotected backups, or overly permissive API responses that reveal more than the caller needs.',
    examples: [
      'An unauthenticated API endpoint returns full user profile records, including other users\' data.',
      'A misconfigured cloud storage bucket is left publicly readable, exposing customer files.',
      'Verbose stack traces reveal internal file paths, framework versions, and database schema.',
      'An attacker uses timing differences in a login form to determine whether a username exists.',
      'Sensitive data is logged in plaintext and later found in centralized log aggregation tools.',
      'A mobile app stores authentication tokens in unencrypted local storage accessible to other apps.',
      'Source maps are deployed to production, exposing original application source code.',
      'A GraphQL API allows introspection in production, revealing the entire internal schema.',
    ],
    mitigations: [
      'Classify data by sensitivity and apply encryption at rest and in transit for anything above "public".',
      'Enforce the principle of least privilege on data access, returning only fields the caller is entitled to.',
      'Disable verbose error messages and stack traces in production; log details server-side only.',
      'Regularly audit cloud storage and database permissions for public or overly broad access.',
      'Mask or redact sensitive fields (PII, secrets, tokens) in logs, error messages, and support tooling.',
      'Disable directory listing, source maps, and debug endpoints in production deployments.',
      'Use constant-time comparison for secrets to prevent timing side-channel attacks.',
      'Apply data loss prevention (DLP) tooling to detect and block exfiltration of sensitive data.',
      'Disable GraphQL introspection and verbose schema errors in production environments.',
      'Encrypt backups and restrict their access to the same standard as production data.',
    ],
    questions: [
      { id: 'id-q1', question: 'Do API responses include more data fields than the client actually needs?', guidance: 'Apply response filtering and per-role field-level authorization on all endpoints.' },
      { id: 'id-q2', question: 'Are cloud storage buckets and object stores audited for public or overly broad access?', guidance: 'Automate scanning for public ACLs and alert immediately on policy drift.' },
      { id: 'id-q3', question: 'Do error messages expose stack traces, file paths, or internal implementation details?', guidance: 'Return generic error messages to clients; log full detail only server-side.' },
      { id: 'id-q4', question: 'Is sensitive data encrypted at rest, including in backups and data warehouse copies?', guidance: 'Verify encryption keys are managed separately (KMS/HSM) from the encrypted data.' },
      { id: 'id-q5', question: 'Can an attacker enumerate valid usernames or accounts through response differences?', guidance: 'Return identical responses and timing for both valid and invalid identifiers.' },
      { id: 'id-q6', question: 'Are secrets (API keys, passwords, tokens) ever written to application or access logs?', guidance: 'Implement log scrubbing/redaction for known secret patterns before persistence.' },
      { id: 'id-q7', question: 'Is production debug tooling, source maps, or admin interfaces reachable from the internet?', guidance: 'Strip debug artifacts from production builds and restrict admin interfaces by network.' },
      { id: 'id-q8', question: 'Are mobile app local storage and caches encrypted for sensitive session data?', guidance: 'Use platform keystore/keychain APIs instead of plaintext shared preferences or files.' },
      { id: 'id-q9', question: 'Does the system leak information via HTTP headers, such as server or framework versions?', guidance: 'Strip or generalize version-revealing headers at the edge/reverse proxy.' },
      { id: 'id-q10', question: 'Are third-party analytics or tracking scripts capturing more data than intended?', guidance: 'Review third-party script permissions and data collection scope regularly.' },
      { id: 'id-q11', question: 'Can directory listing or unindexed file access reveal sensitive files on a web server?', guidance: 'Disable directory listing and verify no sensitive files sit in publicly served directories.' },
      { id: 'id-q12', question: 'Is GraphQL introspection or verbose schema information exposed in production?', guidance: 'Disable introspection in production and rate-limit query complexity.' },
      { id: 'id-q13', question: 'Are database backups encrypted and access-controlled to the same level as production data?', guidance: 'Confirm backup storage is not more permissive than the source system.' },
      { id: 'id-q14', question: 'Can side-channel timing or caching behavior reveal sensitive information indirectly?', guidance: 'Use constant-time operations for secret comparisons and cache-control headers on sensitive pages.' },
      { id: 'id-q15', question: 'Is PII minimized -- collected, retained, and displayed only when strictly necessary?', guidance: 'Apply data minimization and automatic purge/retention policies.' },
      { id: 'id-q16', question: 'Do internal tools used by support or operations staff expose more data than their role requires?', guidance: 'Apply role-based field masking in internal admin panels, not just customer-facing apps.' },
      { id: 'id-q17', question: 'Are exported reports, CSVs, or PDFs stripped of hidden metadata containing sensitive data?', guidance: 'Sanitize export pipelines and check for embedded metadata, comments, or hidden columns.' },
    ],
  },
  {
    key: 'denial_of_service',
    letter: 'D',
    name: 'Denial of Service',
    tagline: 'Degrading or denying legitimate use of a service',
    violates: 'Availability',
    description:
      'Denial of service threats target the availability of a system, degrading performance or making it entirely unusable for legitimate users. DoS can be achieved through resource exhaustion (CPU, memory, disk, bandwidth, connections), application-logic abuse (expensive operations triggered repeatedly), or infrastructure-level flooding. Distributed denial of service (DDoS) uses many sources simultaneously to amplify impact and complicate mitigation.',
    examples: [
      'A volumetric DDoS attack floods network bandwidth with junk traffic from a botnet.',
      'An attacker submits an unbounded regular expression that causes catastrophic backtracking (ReDoS).',
      'An unauthenticated endpoint triggers an expensive database query, exhausting connection pools.',
      'An attacker uploads extremely large files repeatedly, filling available disk space.',
      'Account lockout policies are abused to lock out legitimate users by deliberately failing logins.',
      'A recursive or deeply nested JSON/XML payload exhausts parser memory (billion laughs attack).',
      'An attacker exploits an amplification vulnerability in DNS or NTP to flood a victim with reflected traffic.',
      'A single expensive report-generation feature is called repeatedly to exhaust CPU on shared infrastructure.',
    ],
    mitigations: [
      'Deploy DDoS protection services (scrubbing centers, anycast, CDN) in front of internet-facing infrastructure.',
      'Apply rate limiting and quotas per user, API key, and IP address on all public endpoints.',
      'Set strict timeouts, input size limits, and resource caps on parsers and expensive operations.',
      'Use circuit breakers and bulkheads to isolate failures and prevent cascading resource exhaustion.',
      'Validate regular expressions for catastrophic backtracking risk (avoid nested quantifiers on user input).',
      'Autoscale stateless components and separate expensive workloads onto isolated resource pools.',
      'Implement CAPTCHA or proof-of-work challenges for anonymous, high-cost operations.',
      'Apply connection limits and SYN flood protections at the network and load-balancer layer.',
      'Design account lockout to use progressive delays or risk-based throttling instead of hard lockouts.',
      'Monitor for anomalous traffic patterns and have a documented DDoS incident response runbook.',
    ],
    questions: [
      { id: 'do-q1', question: 'Are public endpoints protected by rate limiting per IP, user, and API key?', guidance: 'Verify limits are enforced at the edge as well as the application layer.' },
      { id: 'do-q2', question: 'Can a single request trigger disproportionately expensive processing (CPU, memory, I/O)?', guidance: 'Profile expensive endpoints and cap input size, pagination, and query complexity.' },
      { id: 'do-q3', question: 'Are regular expressions used on user input reviewed for catastrophic backtracking?', guidance: 'Audit regex patterns for nested quantifiers and test against adversarial input.' },
      { id: 'do-q4', question: 'Is there protection against volumetric network-layer DDoS attacks?', guidance: 'Confirm a scrubbing service, CDN, or anycast network sits in front of public infrastructure.' },
      { id: 'do-q5', question: 'Can account lockout policies be weaponized to deny legitimate users access?', guidance: 'Use progressive delays or risk-based throttling instead of permanent lockouts.' },
      { id: 'do-q6', question: 'Are file upload size, type, and rate limited to prevent storage exhaustion?', guidance: 'Enforce server-side limits independent of client-side checks.' },
      { id: 'do-q7', question: 'Do parsers (JSON, XML, YAML) enforce depth and size limits to avoid resource-exhaustion attacks?', guidance: 'Reject deeply nested or oversized payloads before full parsing begins.' },
      { id: 'do-q8', question: 'Are database connection pools and thread pools isolated per workload to prevent starvation?', guidance: 'Use bulkheads so one noisy tenant or feature cannot exhaust shared resources.' },
      { id: 'do-q9', question: 'Is autoscaling configured with sane upper bounds to avoid runaway cost-based denial of service?', guidance: 'Balance elasticity with budget guardrails and alerting on scaling anomalies.' },
      { id: 'do-q10', question: 'Are timeouts configured on all outbound calls to prevent thread/connection exhaustion from slow dependencies?', guidance: 'Set aggressive timeouts and circuit breakers on every external dependency.' },
      { id: 'do-q11', question: 'Can anonymous users trigger expensive operations without proof-of-work or CAPTCHA friction?', guidance: 'Add friction (CAPTCHA, proof-of-work) to high-cost, low-trust operations.' },
      { id: 'do-q12', question: 'Is there a documented and tested incident response plan for DDoS events?', guidance: 'Run tabletop exercises simulating volumetric and application-layer DDoS scenarios.' },
      { id: 'do-q13', question: 'Are third-party dependencies monitored for outages that could cascade into your own downtime?', guidance: 'Design graceful degradation and fallback behavior when dependencies are unavailable.' },
      { id: 'do-q14', question: 'Can message queues or background job systems be flooded to delay processing for all tenants?', guidance: 'Apply per-tenant queue quotas and priority lanes for critical workloads.' },
      { id: 'do-q15', question: 'Are WebSocket or long-lived connections capped per client to prevent connection exhaustion?', guidance: 'Enforce maximum concurrent connections per identity and idle-timeout reclamation.' },
    ],
  },
  {
    key: 'elevation_of_privilege',
    letter: 'E',
    name: 'Elevation of Privilege',
    tagline: 'Gaining capabilities without proper authorization',
    violates: 'Authorization',
    description:
      'Elevation of privilege threats occur when a user or process gains capabilities beyond what was intended, whether by exploiting a software flaw, misconfiguration, or logic error in the authorization model. This can range from a standard user accessing administrative functions (vertical escalation) to one user accessing another user\'s data (horizontal escalation). Elevation of privilege is often the final step in an attack chain, converting an initial foothold into full system compromise.',
    examples: [
      'A user modifies a hidden "role" parameter in a request to become an administrator.',
      'An insecure direct object reference (IDOR) allows a user to view or edit another user\'s records by changing an ID.',
      'A container escape vulnerability allows code running inside a container to gain host-level access.',
      'A local privilege escalation bug in the OS kernel allows a standard user to obtain root access.',
      'Overly broad IAM policies grant a service more permissions than its function requires.',
      'A misconfigured sudo rule allows a low-privileged user to execute arbitrary commands as root.',
      'An attacker exploits a deserialization vulnerability to execute code with the privileges of the application.',
      'A default or forgotten admin account with a weak password provides direct elevation of privilege.',
    ],
    mitigations: [
      'Enforce authorization checks on every request server-side, never relying on hidden fields or client state.',
      'Apply role-based or attribute-based access control (RBAC/ABAC) consistently across all services.',
      'Follow least privilege for IAM roles, service accounts, and sudoers configuration.',
      'Patch operating systems, containers, and hypervisors promptly to close local privilege escalation paths.',
      'Use object-level authorization checks (not just endpoint-level) to prevent IDOR-style horizontal escalation.',
      'Isolate workloads using containers, sandboxes, or virtualization with minimal shared kernel surface.',
      'Avoid unsafe deserialization of untrusted input; use safe, schema-validated serialization formats.',
      'Regularly audit privileged accounts, remove unused admin access, and rotate default credentials immediately.',
      'Segregate duties so no single account can both request and approve a privileged change.',
      'Use just-in-time privileged access management (PAM) instead of standing administrative access.',
    ],
    questions: [
      { id: 'ep-q1', question: 'Are authorization checks enforced server-side on every request, not inferred from the UI?', guidance: 'Verify hidden buttons or disabled UI elements are not the only control preventing privileged actions.' },
      { id: 'ep-q2', question: 'Can a user access another user\'s resources by manipulating an object ID (IDOR)?', guidance: 'Check that ownership or membership is verified on every object-level operation.' },
      { id: 'ep-q3', question: 'Are IAM roles and service accounts scoped to least privilege for their actual function?', guidance: 'Review policies for wildcard permissions and unused broad grants.' },
      { id: 'ep-q4', question: 'Is privilege escalation possible through container breakout or shared kernel vulnerabilities?', guidance: 'Apply seccomp/AppArmor profiles, rootless containers, and prompt patching.' },
      { id: 'ep-q5', question: 'Can default, forgotten, or shared administrative accounts be discovered and abused?', guidance: 'Inventory all admin accounts and disable/rotate any that are default or unused.' },
      { id: 'ep-q6', question: 'Are deserialization operations performed on untrusted input without validation?', guidance: 'Avoid native deserialization of untrusted data; prefer JSON with strict schema validation.' },
      { id: 'ep-q7', question: 'Is there separation of duties between requesting and approving privileged changes?', guidance: 'Ensure no single individual can both create and approve high-impact changes unilaterally.' },
      { id: 'ep-q8', question: 'Can sudoers or local OS privilege configurations be abused to run arbitrary commands as root?', guidance: 'Audit sudoers files for overly broad NOPASSWD or wildcard command rules.' },
      { id: 'ep-q9', question: 'Are role assignments reviewed periodically to remove excess or stale privileges?', guidance: 'Run periodic access reviews and automatically expire unused privileged roles.' },
      { id: 'ep-q10', question: 'Is just-in-time or time-bound privileged access used instead of standing admin rights?', guidance: 'Adopt PAM tooling that grants elevated access only for a limited, audited window.' },
      { id: 'ep-q11', question: 'Can API mass-assignment allow a user to set privileged fields (e.g., isAdmin) they should not control?', guidance: 'Use allow-lists for writable fields rather than binding entire request bodies to models.' },
      { id: 'ep-q12', question: 'Are local privilege escalation patches applied promptly across operating systems and hypervisors?', guidance: 'Track patch SLAs specifically for privilege-escalation-class CVEs.' },
      { id: 'ep-q13', question: 'Can a lower-trust plugin, extension, or webhook execute with the full privileges of the host application?', guidance: 'Sandbox third-party extensions and apply capability-based permission scopes.' },
      { id: 'ep-q14', question: 'Is multi-tenant isolation enforced so one tenant cannot escalate into another tenant\'s data or compute?', guidance: 'Verify tenant ID is checked on every query, not just at the API gateway.' },
      { id: 'ep-q15', question: 'Are break-glass emergency access procedures logged, time-limited, and reviewed after use?', guidance: 'Ensure emergency privilege grants automatically expire and trigger a mandatory post-use review.' },
    ],
  },
];

/* ============================================================================
   SECTION 2: DREAD DATA
   ========================================================================== */

const DREAD_FACTORS = [
  {
    key: 'damage',
    name: 'Damage Potential',
    question: 'How much damage could result if this threat were successfully exploited?',
    levels: [
      { score: 1, label: 'Minimal', desc: 'No meaningful impact -- cosmetic issue, no data or service affected.' },
      { score: 3, label: 'Minor', desc: 'Limited impact -- a single low-value data point or non-critical feature affected.' },
      { score: 5, label: 'Moderate', desc: 'Individual user data exposed or a single feature made unavailable.' },
      { score: 7, label: 'Major', desc: 'Significant data set exposed, or core functionality degraded for many users.' },
      { score: 9, label: 'Severe', desc: 'Complete system compromise, mass data breach, or total loss of availability.' },
      { score: 10, label: 'Catastrophic', desc: 'Loss of life-safety, regulatory shutdown, or irrecoverable business damage.' },
    ],
  },
  {
    key: 'reproducibility',
    name: 'Reproducibility',
    question: 'How easy is it to reproduce the attack once it is known?',
    levels: [
      { score: 1, label: 'Very Hard', desc: 'Requires a rare race condition or precise timing that is nearly impossible to repeat.' },
      { score: 3, label: 'Hard', desc: 'Works only under specific, uncommon configuration or environmental conditions.' },
      { score: 5, label: 'Moderate', desc: 'Reproducible with some effort; requires specific setup steps or tooling.' },
      { score: 7, label: 'Easy', desc: 'Reproducible reliably by following a documented sequence of steps.' },
      { score: 9, label: 'Very Easy', desc: 'Works every single time with minimal setup, and is trivially scriptable.' },
      { score: 10, label: 'Trivial', desc: 'Works every time with no special conditions; a single click or request.' },
    ],
  },
  {
    key: 'exploitability',
    name: 'Exploitability',
    question: 'What is needed to exploit this threat -- skill, access, and tooling?',
    levels: [
      { score: 1, label: 'Expert Only', desc: 'Requires advanced skills, custom tooling, and privileged internal access.' },
      { score: 3, label: 'Skilled', desc: 'Requires solid security expertise and non-trivial custom exploit development.' },
      { score: 5, label: 'Moderate', desc: 'Requires some technical knowledge; public tooling exists but needs adaptation.' },
      { score: 7, label: 'Novice', desc: 'A junior attacker can exploit this using widely available tools with light modification.' },
      { score: 9, label: 'Automated', desc: 'Exploitable with publicly available scripts or automated scanners.' },
      { score: 10, label: 'Point and Click', desc: 'No skill required; a web browser or a single command is enough.' },
    ],
  },
  {
    key: 'affected_users',
    name: 'Affected Users',
    question: 'How many users or systems would be impacted if this were exploited?',
    levels: [
      { score: 1, label: 'None', desc: 'No users affected, or purely internal/test environment.' },
      { score: 3, label: 'Very Few', desc: 'A small number of users or a single low-value account affected.' },
      { score: 5, label: 'Some', desc: 'A meaningful subset of users, such as one customer segment or region.' },
      { score: 7, label: 'Most', desc: 'A large majority of the user base or several major customers affected.' },
      { score: 9, label: 'All', desc: 'Every user of the system or platform is affected.' },
      { score: 10, label: 'Everyone + Downstream', desc: 'All users plus downstream partners, integrators, or supply-chain consumers.' },
    ],
  },
  {
    key: 'discoverability',
    name: 'Discoverability',
    question: 'How easy is it for an attacker to discover this vulnerability?',
    levels: [
      { score: 1, label: 'Very Hard', desc: 'Requires source code access and deep reverse engineering to find.' },
      { score: 3, label: 'Hard', desc: 'Requires significant probing, fuzzing, or insider knowledge to uncover.' },
      { score: 5, label: 'Moderate', desc: 'Discoverable through standard penetration testing techniques.' },
      { score: 7, label: 'Easy', desc: 'Visible through basic reconnaissance, error messages, or public documentation.' },
      { score: 9, label: 'Very Easy', desc: 'Listed in public vulnerability databases or obvious from casual browsing.' },
      { score: 10, label: 'Public Knowledge', desc: 'Actively exploited in the wild with public proof-of-concept exploits available.' },
    ],
  },
];

function dreadWeightedScore(scores, weights) {
  const w = weights || { damage: 1, reproducibility: 1, exploitability: 1, affected_users: 1, discoverability: 1 };
  let sum = 0;
  let wsum = 0;
  for (const f of DREAD_FACTORS) {
    const val = tmClamp(Number(scores[f.key]) || 0, 0, 10);
    const weight = Number(w[f.key]) || 0;
    sum += val * weight;
    wsum += weight;
  }
  if (wsum === 0) return 0;
  return sum / wsum;
}

function dreadRatingLabel(score) {
  if (score >= 8) return { label: 'Critical', color: '#ff2e63' };
  if (score >= 6) return { label: 'High', color: '#ff5f56' };
  if (score >= 4) return { label: 'Medium', color: '#ffbd2e' };
  if (score >= 1) return { label: 'Low', color: '#27c93f' };
  return { label: 'Informational', color: '#8b98a5' };
}

/* ============================================================================
   SECTION 3: PASTA DATA (Process for Attack Simulation and Threat Analysis)
   ========================================================================== */

const PASTA_STAGES = [
  {
    stage: 1,
    name: 'Define Objectives',
    abbr: 'DO',
    objective: 'Establish the business and security objectives that will drive the entire threat modeling exercise, ensuring the analysis stays anchored to what actually matters to the organization.',
    narrative:
      'The first stage of PASTA is about grounding the exercise in business reality before any technical analysis begins. Teams identify the business objectives of the application or system -- revenue generation, regulatory compliance, customer trust, operational uptime -- and translate them into security objectives that protect those outcomes. This stage also captures compliance and regulatory drivers (PCI DSS, HIPAA, GDPR, SOX) that impose hard requirements on the system, and it defines risk tolerance: how much risk the business is willing to accept versus what must be mitigated. Without this stage, later technical findings have no way to be prioritized against what the organization actually cares about, and threat modeling degenerates into a checklist exercise disconnected from business value.\n\nKey outputs of this stage include a documented list of business objectives, an inventory of compliance obligations, a statement of risk appetite, and identification of key stakeholders who will need to sign off on the resulting risk treatment decisions. This stage should involve business owners, not just security engineers, because the entire point of PASTA is to align technical threat analysis with business impact.',
    activities: [
      'Identify the business objectives the application supports (revenue, brand, operations, customer trust).',
      'Determine applicable compliance and regulatory requirements (PCI DSS, HIPAA, GDPR, SOX, FedRAMP).',
      'Define the organization\'s risk appetite and tolerance thresholds for this system.',
      'Identify key stakeholders (business owners, legal, compliance, engineering leadership).',
      'Establish the scope and boundaries of the threat modeling exercise.',
      'Define success criteria for the threat modeling engagement.',
      'Document the criticality classification of the system (mission-critical, important, standard).',
      'Capture any prior audit findings, incident history, or known risk areas relevant to objectives.',
    ],
    deliverables: [
      'Business objectives statement',
      'Compliance and regulatory requirements matrix',
      'Risk appetite and tolerance document',
      'Stakeholder RACI matrix',
      'Scope and boundary definition',
    ],
  },
  {
    stage: 2,
    name: 'Define Technical Scope',
    abbr: 'DTS',
    objective: 'Define the technical boundaries of the system under analysis, including the application architecture, technology stack, network topology, and infrastructure dependencies.',
    narrative:
      'Where stage one defines "why", stage two defines "what". This stage builds a comprehensive technical inventory of the system: application components, services, APIs, third-party libraries, network segments, cloud resources, and infrastructure dependencies. The technical scope must be detailed enough that data flows and trust boundaries can later be mapped precisely -- vague scoping produces vague threat models. Teams typically produce architecture diagrams, network diagrams, and a software bill of materials (SBOM) during this stage.\n\nThis stage also identifies the attack surface at a technical level: which components are internet-facing, which are internal-only, which handle sensitive data, and which integrate with third parties. Technology stack enumeration (languages, frameworks, database engines, cloud services) feeds directly into later threat enumeration, since many threats are technology-specific (e.g., deserialization threats for Java, prototype pollution for JavaScript). Incomplete technical scoping is one of the most common reasons threat models miss real-world attack paths.',
    activities: [
      'Enumerate all application components, services, and microservices in scope.',
      'Document the full technology stack: languages, frameworks, runtimes, and database engines.',
      'Map network topology, segmentation, and trust zones (DMZ, internal, cloud VPC).',
      'Produce or update architecture diagrams showing component relationships.',
      'Build a software bill of materials (SBOM) listing third-party and open-source dependencies.',
      'Identify all external integrations, APIs, and third-party service dependencies.',
      'Classify which components are internet-facing versus internal-only.',
      'Document infrastructure-as-code, deployment pipelines, and hosting environments (cloud/on-prem).',
    ],
    deliverables: [
      'System architecture diagram',
      'Network topology and trust zone map',
      'Technology stack inventory',
      'Software bill of materials (SBOM)',
      'External integration and dependency list',
    ],
  },
  {
    stage: 3,
    name: 'Application Decomposition',
    abbr: 'AD',
    objective: 'Decompose the application into its constituent parts -- data flows, trust boundaries, entry points, assets, and actors -- to produce the data flow diagrams that later stages will analyze for threats.',
    narrative:
      'Application decomposition is where the technical scope from stage two is transformed into structured data flow diagrams (DFDs). Analysts identify every entry point (login forms, APIs, file uploads, message queues), every actor (users, administrators, external systems), every process (services, functions, business logic), every data store (databases, caches, file systems, queues), and the data flows connecting them. Trust boundaries are drawn wherever data crosses from one privilege or trust level to another -- for example, from the internet into the DMZ, from the DMZ into the internal network, or from a standard user role into an administrative role.\n\nThis decomposition is the structural backbone of the entire threat model: every threat identified in later stages should map back to a specific element in this diagram -- a specific data flow, process, or store. Analysts also identify the assets flowing through the system at this stage (credentials, PII, payment data, intellectual property) so that later impact analysis can be tied to concrete, valuable things worth protecting, not abstract components.',
    activities: [
      'Identify all entry points into the system (UI forms, APIs, file uploads, integrations, admin consoles).',
      'Identify all actors: end users, administrators, external systems, and automated processes.',
      'Enumerate all processes (services, functions, business logic components) handling data.',
      'Enumerate all data stores (databases, caches, queues, file systems, backups).',
      'Draw data flows connecting actors, processes, and data stores.',
      'Draw trust boundaries wherever data crosses privilege or network trust levels.',
      'Classify assets flowing through the system by sensitivity (PII, credentials, payment data, IP).',
      'Validate the decomposition with engineering teams to ensure it reflects the real implementation.',
    ],
    deliverables: [
      'Level-0 and Level-1 data flow diagrams',
      'Trust boundary map',
      'Entry point inventory',
      'Asset classification list',
      'Actor and role inventory',
    ],
  },
  {
    stage: 4,
    name: 'Threat Analysis',
    abbr: 'TA',
    objective: 'Analyze threat intelligence -- both external (industry threat feeds, CVE data, threat actor TTPs) and internal (past incidents, audit findings) -- to identify realistic threats relevant to this specific system.',
    narrative:
      'Stage four shifts from structural analysis to threat intelligence. Rather than brainstorming hypothetical threats in a vacuum, PASTA emphasizes grounding threat identification in real, observed attacker behavior. Analysts consult threat intelligence feeds, industry-specific attack pattern databases (such as MITRE ATT&CK and CAPEC), vendor security bulletins, and internal incident history to build a threat actor profile relevant to the system: who would want to attack this system, what are their capabilities, and what techniques have been used against similar systems in the past.\n\nThis stage produces a prioritized list of realistic threat scenarios mapped to the actors and motivations most likely to target the specific system, rather than a generic catalog. For example, a payment system should weight financially motivated organized crime and carding threat actors heavily, while a system holding government data should weight nation-state espionage actors. This stage bridges pure technical vulnerability analysis (stage five) with real-world attacker relevance, ensuring the threat model reflects genuine risk rather than theoretical possibility.',
    activities: [
      'Review industry threat intelligence feeds and ISAC/ISAO reports relevant to the sector.',
      'Map likely threat actors (script kiddies, organized crime, insiders, nation-state, hacktivists) to the system.',
      'Cross-reference MITRE ATT&CK techniques and CAPEC attack patterns applicable to the technology stack.',
      'Review historical incident data and past penetration test findings for this system or similar systems.',
      'Analyze threat actor motivations, capabilities, and typical targets in this industry.',
      'Prioritize threat scenarios based on actor relevance and historical attack frequency.',
      'Document assumptions about attacker capability levels for later probability estimation.',
      'Identify any active or emerging threat campaigns targeting the technology stack in use.',
    ],
    deliverables: [
      'Threat actor profile and capability matrix',
      'Prioritized threat scenario list',
      'MITRE ATT&CK / CAPEC technique mapping',
      'Threat intelligence summary report',
    ],
  },
  {
    stage: 5,
    name: 'Vulnerability & Weakness Analysis',
    abbr: 'VWA',
    objective: 'Correlate the threats identified in stage four with actual vulnerabilities and weaknesses in the system -- through code review, vulnerability scanning, and architecture analysis -- to identify exploitable attack paths.',
    narrative:
      'Stage five is where threat analysis meets vulnerability reality. Having identified realistic threats and threat actors in stage four, analysts now determine which of those threats have a real exploitation path against the specific system by correlating them with actual weaknesses: results from static application security testing (SAST), dynamic testing (DAST), software composition analysis (SCA) for vulnerable dependencies, infrastructure vulnerability scans, and manual code or architecture review. Weaknesses are commonly cataloged using the Common Weakness Enumeration (CWE) taxonomy, and specific known vulnerabilities using CVE identifiers.\n\nThis stage produces a mapping of threat-to-vulnerability pairs: for each threat scenario identified previously, does a corresponding exploitable weakness actually exist in this system? A threat without a corresponding vulnerability is lower priority; a vulnerability with no realistic threat actor is also lower priority. It is the intersection -- a credible threat actor combined with an exploitable weakness -- that defines genuine risk and drives the attack simulation performed in stage six.',
    activities: [
      'Run static application security testing (SAST) across the codebase.',
      'Run dynamic application security testing (DAST) against running instances.',
      'Perform software composition analysis (SCA) to identify vulnerable third-party dependencies.',
      'Conduct infrastructure and network vulnerability scanning.',
      'Perform manual code review of critical security-relevant components (auth, crypto, access control).',
      'Correlate identified weaknesses (CWE) with known vulnerabilities (CVE) where applicable.',
      'Map each stage-4 threat scenario to a corresponding real vulnerability or weakness, if one exists.',
      'Score identified vulnerabilities using CVSS or an equivalent severity framework.',
    ],
    deliverables: [
      'Vulnerability scan and SAST/DAST results',
      'Software composition analysis (SCA) report',
      'Threat-to-vulnerability correlation matrix',
      'CVSS-scored vulnerability list',
    ],
  },
  {
    stage: 6,
    name: 'Attack Modeling / Simulation',
    abbr: 'AM',
    objective: 'Simulate realistic attack scenarios -- via attack trees, attack graphs, or red team exercises -- to validate that identified threat-vulnerability pairs are genuinely exploitable end-to-end and to understand full attack paths.',
    narrative:
      'Stage six moves from analysis to active simulation. Using the threat-vulnerability pairs identified in stage five, analysts construct attack trees or attack graphs that model the specific sequence of steps an attacker would need to take to achieve a given objective -- for example, "exfiltrate customer PII" or "achieve remote code execution on the payment processing host". This stage often includes actual penetration testing or red team exercises to empirically validate whether the theorized attack paths work in practice, and to discover chained vulnerabilities that individually seem low-risk but combine into a critical attack path.\n\nAttack simulation reveals whether compensating controls (network segmentation, WAF rules, monitoring) actually stop an attack in practice, not just in theory. This stage frequently uncovers that "low severity" individual findings chain together into "critical" end-to-end compromises, which is a key reason PASTA emphasizes simulation over simply listing vulnerabilities in isolation. The output feeds directly into stage seven\'s risk and impact analysis, since a validated, working attack path carries far more weight than a theoretical one.',
    activities: [
      'Build attack trees for the highest-priority threat-vulnerability pairs identified in stage five.',
      'Model attacker decision points, required capabilities, and alternative paths at each tree node.',
      'Conduct penetration testing or red team exercises to validate theorized attack paths empirically.',
      'Identify vulnerability chains where individually low-risk issues combine into a critical attack path.',
      'Test whether existing compensating controls (WAF, IDS/IPS, segmentation) actually block the simulated attack.',
      'Document successful and unsuccessful attack paths with supporting evidence.',
      'Estimate the likelihood of each validated attack path being exploited in the wild.',
      'Update the threat scenario list based on empirical simulation results.',
    ],
    deliverables: [
      'Attack tree diagrams for priority threat scenarios',
      'Penetration test / red team findings report',
      'Validated attack path documentation with evidence',
      'Compensating control effectiveness assessment',
    ],
  },
  {
    stage: 7,
    name: 'Risk & Impact Analysis',
    abbr: 'RIA',
    objective: 'Quantify the business risk of each validated attack path by combining likelihood and impact, then produce prioritized, actionable risk treatment recommendations tied back to the business objectives from stage one.',
    narrative:
      'The final stage closes the loop back to stage one: business objectives. Having validated real attack paths in stage six, analysts now calculate the business risk of each one -- typically combining likelihood (informed by threat actor capability and attack complexity from earlier stages) with impact (informed by the asset classification and business objectives established at the start). This produces a risk register prioritized in terms the business understands: financial loss, regulatory exposure, reputational damage, and operational disruption, not just technical severity scores.\n\nThis stage produces concrete risk treatment recommendations: mitigate (implement a specific control), transfer (insurance or contractual risk shifting), accept (formally document and sign off on accepted risk), or avoid (remove the feature or capability entirely). Each recommendation should include estimated cost of mitigation versus cost of the risk materializing, enabling business stakeholders to make informed, prioritized investment decisions. The final deliverable is a comprehensive threat model report that traces a clear line from business objective, through technical architecture and validated attack paths, to a prioritized, costed risk treatment plan -- which is what distinguishes PASTA from purely technical threat modeling methodologies.',
    activities: [
      'Calculate likelihood for each validated attack path based on actor capability and attack complexity.',
      'Calculate business impact for each attack path based on asset value and business objectives.',
      'Combine likelihood and impact into a prioritized risk score for each threat scenario.',
      'Develop risk treatment recommendations: mitigate, transfer, accept, or avoid.',
      'Estimate the cost of mitigation versus the cost of risk materialization for prioritization.',
      'Map risk treatment recommendations to responsible owners and target remediation timelines.',
      'Produce an executive summary connecting technical findings back to business objectives.',
      'Present the finalized risk register and treatment plan to stakeholders for sign-off.',
    ],
    deliverables: [
      'Quantified risk register (likelihood x impact per threat)',
      'Risk treatment plan (mitigate / transfer / accept / avoid)',
      'Cost-benefit analysis for proposed mitigations',
      'Executive summary report',
      'Stakeholder sign-off documentation',
    ],
  },
];

/* ============================================================================
   SECTION 4: LINDDUN DATA (privacy threat modeling)
   ========================================================================== */

const LINDDUN_CATEGORIES = [
  {
    key: 'linking',
    letter: 'L',
    name: 'Linking',
    tagline: 'Associating data items or user actions to learn more about an individual or group',
    description:
      'Linking threats arise when disparate pieces of data -- individually innocuous -- can be combined or correlated to build a richer profile of an individual than any single piece of data would reveal. Linking can occur across sessions, across services, or across supposedly anonymized data sets. Even data that has been de-identified can often be re-linked to specific individuals when combined with auxiliary data sources, a phenomenon well documented in re-identification research. Linking undermines the principle of purpose limitation: data collected for one purpose becomes a tool for unrelated profiling.',
    examples: [
      'Combining "anonymized" location data with public social media check-ins to re-identify individuals.',
      'Using a persistent device fingerprint to link a user\'s activity across multiple unrelated websites.',
      'Correlating purchase histories across merchants who share a common analytics or ad-tech provider.',
      'Linking pseudonymous forum accounts to real identities via writing-style analysis.',
      'Combining hospital discharge records with voter registration data to re-identify patients.',
      'Using advertising IDs to link app usage patterns across a user\'s entire device.',
      'Correlating timestamps across services to infer that two pseudonymous accounts belong to one person.',
      'Cross-referencing loyalty card purchase data with public social media posts to build a shopping profile.',
    ],
    mitigations: [
      'Avoid persistent identifiers where session-scoped or rotating identifiers would suffice.',
      'Apply k-anonymity, l-diversity, or differential privacy techniques to shared or published data sets.',
      'Segregate data by purpose so combining data sets requires deliberate, auditable cross-system access.',
      'Rotate advertising and analytics identifiers regularly and support user-initiated resets.',
      'Minimize the granularity of timestamps and location data shared with third parties.',
      'Conduct re-identification risk assessments before publishing or sharing "anonymized" data sets.',
    ],
  },
  {
    key: 'identifying',
    letter: 'I',
    name: 'Identifying',
    tagline: 'Learning the identity of an individual, directly or through inference',
    description:
      'Identifying threats involve directly or indirectly learning who a specific individual is, even when a system was designed to operate on pseudonymous or anonymous data. This can happen through explicit identifiers leaking (names, emails, government IDs), through quasi-identifiers that narrow the population to a single person (zip code plus birth date plus gender), or through behavioral fingerprinting that uniquely distinguishes one user from all others without ever collecting a formal identifier.',
    examples: [
      'A "anonymous" survey response is re-identified because the combination of job title, department, and location is unique within the company.',
      'Browser and device fingerprinting uniquely identifies a user across sessions without cookies.',
      'A support ticket system exposes a customer\'s full name in a URL meant to be a pseudonymous reference.',
      'Metadata embedded in uploaded documents (author name, device ID) reveals the uploader\'s identity.',
      'Voice or gait biometric analysis identifies an individual from supposedly de-identified audio/video.',
      'Public records combined with a single quasi-identifier (zip + birth date + gender) re-identify most individuals.',
    ],
    mitigations: [
      'Strip identifying metadata from uploaded files and shared documents before storage or distribution.',
      'Use robust pseudonymization with cryptographically strong, non-reversible tokens.',
      'Limit the number of quasi-identifiers collected together in any single data set.',
      'Apply differential privacy noise to aggregate statistics that could otherwise pinpoint individuals.',
      'Regularly test whether "anonymized" outputs can be re-identified using available auxiliary data.',
      'Restrict browser/device fingerprinting and disclose its use transparently where it is necessary.',
    ],
  },
  {
    key: 'non_repudiation',
    letter: 'N',
    name: 'Non-repudiation',
    tagline: 'Being unable to deny having performed a privacy-relevant action',
    description:
      'In the privacy context, non-repudiation is inverted from its security meaning: rather than being a desirable property (proving who did what), unwanted non-repudiation is a privacy threat when it strips individuals of plausible deniability for sensitive actions -- reading an article, visiting a support group page, or expressing an opinion -- that they may have a legitimate interest in keeping private or deniable. Systems that permanently and undeniably log every user action can chill free expression and create durable evidence that can later be used against the individual in contexts far removed from the original purpose.',
    examples: [
      'A health information portal logs every article a user reads, undeniably proving interest in a specific condition.',
      'An anonymous whistleblower tip system inadvertently retains metadata proving who submitted a report.',
      'A messaging app retains cryptographic proof of message authorship that undermines "off the record" expectations.',
      'Browsing history tied to an authenticated account cannot be plausibly denied even years later.',
      'A voting or petition system retains individual-level records instead of aggregate-only tallies.',
    ],
    mitigations: [
      'Support deniable or ephemeral messaging modes where users have a legitimate privacy interest.',
      'Aggregate or anonymize logs for sensitive categories of activity (health, political, religious topics).',
      'Provide true anonymous reporting channels that do not retain identity-linkable metadata at all.',
      'Set short, purpose-limited retention periods for logs of sensitive user activity.',
      'Give users the ability to review and delete their own activity history.',
    ],
  },
  {
    key: 'detecting',
    letter: 'D',
    name: 'Detecting',
    tagline: 'Deducing the involvement of an individual through observation, without accessing content',
    description:
      'Detecting threats involve inferring facts about an individual purely from the observable existence or pattern of their interactions with a system, without ever needing to see the actual content of those interactions. The mere fact that encrypted traffic is flowing to a particular service, that a device pings a specific server, or that a user\'s calendar shows a recurring blocked-out slot can reveal sensitive information through traffic analysis or metadata alone, even under strong encryption.',
    examples: [
      'Traffic analysis reveals a user is communicating with a specific whistleblower-support or legal-aid service, even though the content is encrypted.',
      'The size and timing pattern of encrypted messages reveals which pre-defined message template was sent.',
      'A device periodically checking in with a specific health-app server reveals a medical condition to a network observer.',
      'Calendar free/busy metadata reveals attendance at a support group without exposing the event title.',
      'Cell tower or Wi-Fi association patterns reveal visits to sensitive locations (clinics, shelters, places of worship).',
    ],
    mitigations: [
      'Use traffic padding or constant-rate transmission to obscure message size and timing patterns.',
      'Route sensitive-service traffic through common, shared infrastructure to avoid destination fingerprinting.',
      'Minimize metadata exposed in calendar, presence, and status features by default.',
      'Offer onion-routing or mixnet-based transport for services with high sensitivity to traffic analysis.',
      'Avoid predictable check-in intervals for background sync of sensitive-category applications.',
    ],
  },
  {
    key: 'data_disclosure',
    letter: 'D',
    name: 'Data Disclosure',
    tagline: 'Excessive collection, storage, or sharing of personal data beyond what is necessary',
    description:
      'Data disclosure threats mirror the security concept of information disclosure but focus specifically on personal data and the privacy principle of data minimization. This includes over-collection (gathering more personal data than a feature actually requires), over-retention (keeping data long after its purpose has been fulfilled), and over-sharing (passing personal data to third parties, analytics vendors, or advertising partners beyond what users reasonably expect or have consented to).',
    examples: [
      'A signup form collects date of birth, gender, and address for a feature that only needs an email address.',
      'User data is retained indefinitely with no automated deletion policy after account closure.',
      'A mobile SDK silently forwards precise location and contact-list data to third-party ad networks.',
      'Customer support tools display full payment card and government ID numbers to every support agent, regardless of need.',
      'A data broker aggregates and resells personal data collected for an unrelated original purpose.',
      'Analytics tools capture full-session replay including form field content typed but never submitted.',
    ],
    mitigations: [
      'Apply data minimization: collect only fields strictly necessary for the stated purpose.',
      'Implement automated retention and deletion policies tied to the original purpose of collection.',
      'Audit third-party SDKs and vendors for the actual scope of data they collect and transmit.',
      'Mask or redact sensitive fields in internal tools based on the specific need of each role.',
      'Provide clear, specific consent mechanisms rather than broad, bundled consent for unrelated uses.',
      'Conduct data protection impact assessments (DPIAs) before launching features that process new categories of personal data.',
    ],
  },
  {
    key: 'unawareness',
    letter: 'U',
    name: 'Unawareness',
    tagline: 'Individuals are not adequately informed about how their data is collected, used, or shared',
    description:
      'Unawareness threats occur when data subjects lack the transparency they need to understand what is happening to their personal data, undermining informed consent and their ability to exercise privacy rights. This includes buried or overly broad privacy policies, "dark pattern" consent flows designed to obtain agreement without genuine understanding, undisclosed data sharing with third parties, and features that process personal data in ways a reasonable user would not expect.',
    examples: [
      'A privacy policy is written in dense legal language that obscures rather than clarifies actual data practices.',
      'Cookie consent banners use dark patterns that make "accept all" one click but "reject all" require five.',
      'A mobile app requests broad permissions (contacts, microphone) with no in-context explanation of why.',
      'Data is shared with an undisclosed list of "partners" referenced only vaguely in the privacy policy.',
      'Users are unaware that a "free" service monetizes their behavioral data through targeted advertising.',
      'Default settings enable maximum data sharing, requiring users to actively discover and opt out.',
    ],
    mitigations: [
      'Write privacy notices in plain, specific language describing exactly what is collected and why.',
      'Use privacy-by-default settings that require an active opt-in for non-essential data sharing.',
      'Provide contextual, just-in-time explanations for sensitive permission requests.',
      'Publish a complete, named list of third-party data recipients rather than vague category references.',
      'Design consent flows with symmetric effort for accepting and rejecting (no dark patterns).',
      'Offer an accessible privacy dashboard where users can see and control exactly what has been collected.',
    ],
  },
  {
    key: 'non_compliance',
    letter: 'N',
    name: 'Non-compliance',
    tagline: 'Failing to adhere to legislation, regulation, or organizational privacy policy',
    description:
      'Non-compliance threats capture the risk that a system fails to meet applicable privacy laws, regulations, industry standards, or the organization\'s own published privacy commitments. This is distinct from the other six LINDDUN categories in that it is a governance and process threat rather than a purely technical one -- though it is frequently the downstream consequence of the other six categories going unaddressed. Non-compliance carries direct legal, financial, and reputational consequences.',
    examples: [
      'A system fails to honor GDPR data subject access, rectification, or erasure requests within required timeframes.',
      'Personal data of EU residents is transferred to a jurisdiction without an adequate legal transfer mechanism.',
      'A children\'s app collects personal data without verifiable parental consent required by COPPA.',
      'A published privacy policy commits to practices the actual system does not implement.',
      'Breach notification obligations are missed because the organization lacks a documented incident response process for personal data breaches.',
      'Health data is processed without the safeguards required under HIPAA\'s Privacy and Security Rules.',
    ],
    mitigations: [
      'Maintain a live compliance register mapping applicable regulations to specific system controls.',
      'Implement automated tooling to fulfill data subject access, rectification, and erasure requests within legal deadlines.',
      'Conduct regular privacy audits comparing published policy commitments against actual system behavior.',
      'Establish documented, tested breach notification procedures meeting the shortest applicable regulatory deadline.',
      'Use standard contractual clauses or equivalent mechanisms for any cross-border personal data transfers.',
      'Engage legal and compliance teams early in the design of features that process regulated categories of data.',
    ],
  },
];

/* ============================================================================
   SECTION 5: DATA FLOW DIAGRAM (DFD) REFERENCE DATA
   ========================================================================== */

const DFD_ELEMENTS = [
  {
    key: 'external_entity',
    name: 'External Entity / Actor',
    shape: 'Rectangle',
    symbol: '[ ]',
    description:
      'Represents a person, organization, or external system that interacts with the system under analysis but lies outside its control -- for example, an end user, an administrator, or a third-party API. External entities are sources or sinks of data flows and are never directly analyzed for internal threats; the boundary between an external entity and the system is almost always a trust boundary.',
    strideRelevance: ['Spoofing'],
    examples: ['End user', 'Third-party payment gateway', 'External auditor', 'Partner API consumer', 'IoT sensor device'],
  },
  {
    key: 'process',
    name: 'Process',
    shape: 'Circle / Rounded Rectangle',
    symbol: '( )',
    description:
      'Represents any unit of work that transforms, routes, or acts upon data -- a function, a microservice, an application server, or a business logic component. Processes are where most STRIDE threats concentrate because they are the active components making decisions about data.',
    strideRelevance: ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'],
    examples: ['Authentication service', 'Order processing engine', 'Report generator', 'Notification dispatcher', 'API gateway'],
  },
  {
    key: 'data_store',
    name: 'Data Store',
    shape: 'Open-ended Rectangle / Parallel Lines',
    symbol: '=  =',
    description:
      'Represents data at rest -- a database, file system, cache, message queue, or configuration store. Data stores are typically passive and cannot spoof or elevate privilege themselves, but they are prime targets for tampering and information disclosure and must be analyzed for repudiation if they hold audit-relevant records.',
    strideRelevance: ['Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service'],
    examples: ['Relational database', 'Object storage bucket', 'Redis cache', 'Message queue', 'Log aggregation store', 'Backup archive'],
  },
  {
    key: 'data_flow',
    name: 'Data Flow',
    shape: 'Arrow',
    symbol: '-->',
    description:
      'Represents the movement of data between two elements -- an external entity, process, or data store. Every data flow that crosses a trust boundary is a candidate location for tampering and information disclosure threats, and should be evaluated for whether it is encrypted, authenticated, and integrity-protected.',
    strideRelevance: ['Tampering', 'Information Disclosure', 'Denial of Service'],
    examples: ['HTTPS API request', 'Database query', 'Message queue publish', 'File upload', 'Webhook callback'],
  },
  {
    key: 'trust_boundary',
    name: 'Trust Boundary',
    shape: 'Dashed Line / Box',
    symbol: '- - -',
    description:
      'Represents a boundary where data or control crosses from one level of trust or privilege to another -- for example, from the public internet into a DMZ, from a DMZ into an internal network, or from a standard user role into an administrative role. Trust boundaries are where the majority of meaningful threats live, because they mark points where an assumption of trust must be explicitly verified rather than implicitly granted.',
    strideRelevance: ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'],
    examples: ['Internet-to-DMZ boundary', 'DMZ-to-internal-network boundary', 'User-to-admin privilege boundary', 'Tenant-to-tenant boundary in multi-tenant systems', 'On-prem-to-cloud boundary'],
  },
  {
    key: 'multi_process',
    name: 'Multi-Process (Composite Process)',
    shape: 'Double-outlined Circle',
    symbol: '(( ))',
    description:
      'Represents a process composed of multiple sub-processes not yet decomposed in the current diagram level -- used in a Level-0 (context) diagram before drilling down into a Level-1 diagram that expands the composite process into its constituent parts.',
    strideRelevance: ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'],
    examples: ['"Payment Processing Subsystem" at Level-0', '"Identity Platform" at Level-0'],
  },
  {
    key: 'bidirectional_flow',
    name: 'Bidirectional Data Flow',
    shape: 'Double-headed Arrow',
    symbol: '<-->',
    description:
      'Represents a request/response or two-way synchronization data flow between elements, common in RPC calls, WebSocket connections, or database transactions requiring acknowledgment. Both directions must be independently analyzed since the threats affecting the request often differ from those affecting the response.',
    strideRelevance: ['Tampering', 'Information Disclosure', 'Denial of Service'],
    examples: ['REST request/response pair', 'WebSocket duplex channel', 'Database transaction commit/ack', 'gRPC bidirectional stream'],
  },
];

const DFD_TRUST_BOUNDARY_PATTERNS = [
  { name: 'Internet to DMZ', description: 'The boundary between untrusted public internet traffic and the demilitarized zone hosting internet-facing services. Requires strong input validation, WAF, and rate limiting.' },
  { name: 'DMZ to Internal Network', description: 'The boundary between internet-facing services and internal-only systems (databases, internal APIs). Requires firewall rules, network segmentation, and no direct internet-to-internal routing.' },
  { name: 'User to Administrator Privilege', description: 'The boundary between standard user capabilities and administrative capabilities within the same application. Requires re-authentication or step-up MFA before crossing.' },
  { name: 'Tenant to Tenant (Multi-tenancy)', description: 'The boundary isolating one customer/tenant\'s data and compute from another\'s in a shared multi-tenant system. Requires tenant ID verification on every data access, not just at the API gateway.' },
  { name: 'On-Premises to Cloud', description: 'The boundary between an organization\'s owned infrastructure and third-party cloud provider infrastructure. Requires encrypted transit (VPN/Direct Connect) and clear data residency controls.' },
  { name: 'First-Party to Third-Party Integration', description: 'The boundary between systems the organization controls and external partner or vendor systems. Requires scoped API credentials, contractual data handling agreements, and monitoring of third-party access.' },
  { name: 'Human to Automated Process', description: 'The boundary between a live human decision-maker and an automated system acting on their behalf (bots, scheduled jobs, AI agents). Requires human-in-the-loop approval gates for high-impact automated actions.' },
  { name: 'Development to Production Environment', description: 'The boundary between lower environments (dev, staging) and production. Requires separate credentials, no production data in lower environments, and controlled promotion pipelines.' },
];

/* ============================================================================
   SECTION 6: THREAT LIBRARY -- SPOOFING (45 threats)
   ========================================================================== */

const THREAT_LIBRARY_SPOOFING = [
  { id: 'SP-001', title: 'Credential stuffing against login endpoint', severity: 'High', cwe: 'CWE-307', description: 'Attackers use lists of breached username/password pairs from other services to automate login attempts, exploiting password reuse.', example: 'A botnet submits thousands of login attempts per minute using a leaked credential dump from an unrelated breach.', mitigation: 'Enforce rate limiting, CAPTCHA after repeated failures, breached-password screening at signup, and mandatory MFA.' },
  { id: 'SP-002', title: 'Phishing for credentials via look-alike domain', severity: 'High', cwe: 'CWE-1021', description: 'An attacker registers a domain visually similar to the legitimate site and harvests credentials through a cloned login page.', example: 'A user receives an email linking to "darknode-login.net" instead of the real domain and enters their password.', mitigation: 'Deploy DMARC/SPF/DKIM, brand-monitor for look-alike domains, enforce FIDO2 hardware keys resistant to phishing.' },
  { id: 'SP-003', title: 'Session token prediction', severity: 'High', cwe: 'CWE-330', description: 'Session identifiers generated with weak or predictable entropy allow an attacker to guess valid session tokens.', example: 'Session IDs increment sequentially, letting an attacker enumerate active sessions.', mitigation: 'Use a cryptographically secure random number generator with at least 128 bits of entropy for session tokens.' },
  { id: 'SP-004', title: 'Session fixation', severity: 'Medium', cwe: 'CWE-384', description: 'An attacker sets a known session ID on a victim before authentication, then hijacks the session once the victim logs in.', example: 'An attacker sends a link containing a pre-set session ID; the victim logs in and the attacker reuses that same ID.', mitigation: 'Regenerate the session identifier immediately upon successful authentication.' },
  { id: 'SP-005', title: 'Man-in-the-middle credential interception', severity: 'High', cwe: 'CWE-300', description: 'An attacker intercepts network traffic between client and server to capture authentication material transmitted without adequate protection.', example: 'A rogue Wi-Fi access point captures login form submissions sent over an unencrypted connection.', mitigation: 'Enforce TLS 1.2+ everywhere, HSTS, and certificate pinning on mobile/desktop clients.' },
  { id: 'SP-006', title: 'DNS cache poisoning / spoofing', severity: 'High', cwe: 'CWE-350', description: 'An attacker corrupts DNS resolver cache entries to redirect users to an attacker-controlled server impersonating the legitimate service.', example: 'Users attempting to reach the real login domain are silently redirected to a phishing clone.', mitigation: 'Deploy DNSSEC validation and use trusted, hardened resolvers.' },
  { id: 'SP-007', title: 'ARP spoofing on local network', severity: 'Medium', cwe: 'CWE-300', description: 'An attacker on the same local network segment sends forged ARP replies to associate their MAC address with a legitimate IP, intercepting traffic.', example: 'An attacker on office Wi-Fi impersonates the default gateway to intercept internal traffic.', mitigation: 'Enable dynamic ARP inspection and DHCP snooping on managed switches.' },
  { id: 'SP-008', title: 'Forged email sender header (email spoofing)', severity: 'Medium', cwe: 'CWE-290', description: 'An attacker forges the "From" header of an email to impersonate a trusted sender such as a company executive.', example: 'A CEO fraud email requests an urgent wire transfer, appearing to come from the CFO\'s address.', mitigation: 'Enforce SPF, DKIM, and DMARC with a reject/quarantine policy on the sending domain.' },
  { id: 'SP-009', title: 'IP address spoofing to bypass allow-lists', severity: 'Medium', cwe: 'CWE-290', description: 'An attacker forges the source IP address of packets to appear to originate from a trusted, allow-listed network.', example: 'Firewall rules allow-listing a partner IP are bypassed by crafting packets with a spoofed source address.', mitigation: 'Use authenticated tunnels (IPsec/mTLS) instead of relying on IP address as the sole trust signal; enable ingress/egress filtering (BCP38).' },
  { id: 'SP-010', title: 'Rogue Wi-Fi access point (evil twin)', severity: 'High', cwe: 'CWE-295', description: 'An attacker sets up a wireless access point broadcasting the same SSID as a legitimate corporate network to capture credentials and traffic.', example: 'Employees near a coffee shop connect to a fake "CorpWiFi" network that harvests VPN credentials.', mitigation: 'Use 802.1X certificate-based Wi-Fi authentication and educate users to verify network certificates.' },
  { id: 'SP-011', title: 'JWT signature bypass ("alg: none" attack)', severity: 'Critical', cwe: 'CWE-347', description: 'A JWT library accepts tokens with the algorithm set to "none" or allows algorithm confusion, letting an attacker forge tokens without a valid signature.', example: 'An attacker crafts a JWT with alg:none and a modified payload claiming administrator privileges.', mitigation: 'Explicitly allow-list accepted signing algorithms server-side and reject "none" and unexpected algorithm values.' },
  { id: 'SP-012', title: 'OAuth token replay across services', severity: 'High', cwe: 'CWE-294', description: 'An OAuth access token issued for one service or audience is accepted and reused by another service that fails to validate the intended audience.', example: 'A token meant for a low-privilege reporting API is replayed against a higher-privilege administrative API.', mitigation: 'Validate the "aud" (audience) claim strictly on every resource server and issue narrowly scoped tokens.' },
  { id: 'SP-013', title: 'SAML assertion forgery via XML signature wrapping', severity: 'Critical', cwe: 'CWE-347', description: 'An attacker manipulates the XML structure of a signed SAML assertion so the signature validates against one element while the application processes a different, attacker-controlled element.', example: 'A wrapped assertion changes the NameID to an administrator account while the original signed block still validates.', mitigation: 'Use a SAML library that binds signature validation strictly to the processed element, not the document as a whole.' },
  { id: 'SP-014', title: 'Biometric spoofing (presentation attack)', severity: 'Medium', cwe: 'CWE-290', description: 'An attacker uses a photograph, mask, or synthetic fingerprint to bypass biometric authentication that lacks liveness detection.', example: 'A high-resolution photo of a user\'s face bypasses a facial recognition unlock feature.', mitigation: 'Implement liveness detection and multi-modal biometric verification.' },
  { id: 'SP-015', title: 'Default or hard-coded device credentials', severity: 'High', cwe: 'CWE-798', description: 'IoT or embedded devices ship with a default username/password that is never changed, allowing trivial impersonation of the device or takeover.', example: 'A network of IP cameras is compromised using the factory default "admin/admin" credential.', mitigation: 'Require unique per-device credentials generated at manufacturing and force credential rotation on first use.' },
  { id: 'SP-016', title: 'Clickjacking-enabled credential capture', severity: 'Medium', cwe: 'CWE-1021', description: 'An attacker overlays an invisible iframe of a legitimate login form over a malicious page, tricking users into submitting credentials to an attacker-controlled flow.', example: 'A "claim your prize" page invisibly overlays the real login iframe, capturing keystrokes.', mitigation: 'Set X-Frame-Options/Content-Security-Policy frame-ancestors to prevent framing of sensitive pages.' },
  { id: 'SP-017', title: 'Bypassing SSO via a legacy authentication endpoint', severity: 'High', cwe: 'CWE-288', description: 'An older authentication path that predates SSO adoption remains active and lacks the same security controls, allowing an attacker to bypass centralized identity policy.', example: 'A legacy XML-RPC login endpoint still accepts direct username/password, bypassing the SSO-enforced MFA requirement.', mitigation: 'Inventory and decommission all legacy authentication entry points once SSO is enforced.' },
  { id: 'SP-018', title: 'Bluetooth impersonation attack', severity: 'Medium', cwe: 'CWE-290', description: 'An attacker exploits weak Bluetooth pairing to impersonate a trusted paired device.', example: 'An attacker impersonates a trusted fitness tracker to inject false data or intercept synced health data.', mitigation: 'Use Bluetooth LE Secure Connections with out-of-band pairing verification.' },
  { id: 'SP-019', title: 'Caller ID / SMS sender spoofing for smishing', severity: 'Medium', cwe: 'CWE-290', description: 'An attacker forges the sender ID of an SMS or phone call to impersonate a bank, delivery company, or internal IT helpdesk.', example: 'A spoofed SMS appearing to be from the company IT helpdesk requests the user\'s MFA code.', mitigation: 'Educate users that MFA codes are never requested via SMS reply, and use app-based push authentication instead.' },
  { id: 'SP-020', title: 'API key leaked in public code repository', severity: 'High', cwe: 'CWE-798', description: 'A developer accidentally commits an API key or service credential to a public source repository, letting an attacker impersonate the service.', example: 'A cloud provider access key is discovered in a public GitHub repo within minutes by an automated scanner and used to spin up cryptomining instances.', mitigation: 'Use secret scanning on commits/pushes, short-lived credentials, and immediate rotation upon exposure.' },
  { id: 'SP-021', title: 'Certificate authority compromise / mis-issuance', severity: 'Critical', cwe: 'CWE-295', description: 'An attacker obtains a fraudulently issued TLS certificate for a domain they do not control, enabling undetectable impersonation of the legitimate service.', example: 'A compromised CA issues a valid certificate for a bank\'s domain to an attacker, enabling an undetectable MITM.', mitigation: 'Implement Certificate Transparency monitoring and HTTP Public Key Pinning or CAA DNS records.' },
  { id: 'SP-022', title: 'Replay of captured authentication handshake', severity: 'Medium', cwe: 'CWE-294', description: 'An attacker captures a valid authentication handshake and replays it later to gain access without knowing the underlying secret.', example: 'A captured Kerberos ticket is replayed within its validity window to access a service.', mitigation: 'Use nonces, timestamps, and short validity windows on authentication handshakes to prevent replay.' },
  { id: 'SP-023', title: 'Typosquatting package name in dependency spoofing', severity: 'High', cwe: 'CWE-829', description: 'An attacker publishes a malicious package with a name similar to a popular legitimate package, hoping developers mistype the install command.', example: 'A developer runs "npm install reqeusts" instead of "requests", installing a credential-stealing package.', mitigation: 'Use lockfiles, verify package names carefully, and restrict installs to a vetted internal registry mirror.' },
  { id: 'SP-024', title: 'Impersonating an internal service via unauthenticated service mesh call', severity: 'High', cwe: 'CWE-306', description: 'A microservice accepts calls from any source on the internal network without verifying caller identity, allowing a compromised or rogue workload to impersonate a trusted service.', example: 'A compromised low-privilege pod calls the billing service directly, which trusts all internal-network callers implicitly.', mitigation: 'Deploy mutual TLS and service identity verification (e.g., SPIFFE/SPIRE) within the service mesh.' },
  { id: 'SP-025', title: 'Fake mobile app impersonating brand in app store', severity: 'Medium', cwe: 'CWE-451', description: 'An attacker publishes a counterfeit mobile application that mimics a legitimate brand\'s look and feel to harvest credentials or payment data.', example: 'A fake "DarkNode Security" app appears in a third-party app store and prompts users for their real login credentials.', mitigation: 'Monitor app stores for brand impersonation, use official app-store badges only, and code-sign official releases.' },
  { id: 'SP-026', title: 'Cross-Site Request Forgery enabling action impersonation', severity: 'Medium', cwe: 'CWE-352', description: 'An attacker tricks an authenticated user\'s browser into submitting a forged request, effectively impersonating the user\'s intent without their knowledge.', example: 'A hidden form on a malicious page auto-submits a password change request using the victim\'s existing session cookie.', mitigation: 'Use anti-CSRF tokens, SameSite cookies, and re-authentication for sensitive state-changing actions.' },
  { id: 'SP-027', title: 'Weak password reset token allowing account takeover', severity: 'High', cwe: 'CWE-640', description: 'A password reset token is predictable, reused, or insufficiently random, allowing an attacker to reset another user\'s password and impersonate them.', example: 'Reset tokens are generated from a timestamp and are guessable within a narrow window.', mitigation: 'Use cryptographically random, single-use, time-limited reset tokens delivered only to verified out-of-band channels.' },
  { id: 'SP-028', title: 'Man-in-the-middle on OAuth authorization code flow without PKCE', severity: 'High', cwe: 'CWE-294', description: 'A public OAuth client without PKCE is vulnerable to interception of the authorization code, allowing an attacker to complete the token exchange as the victim.', example: 'A malicious app registered with the same custom URI scheme intercepts the OAuth redirect and completes the code exchange.', mitigation: 'Require PKCE (Proof Key for Code Exchange) for all public/native OAuth clients.' },
  { id: 'SP-029', title: 'Impersonation via leaked service account key in container image', severity: 'High', cwe: 'CWE-798', description: 'A cloud service account key is baked into a container image layer and later extracted by anyone with pull access to the image.', example: 'An attacker pulls a public container image and extracts an embedded GCP service account JSON key.', mitigation: 'Never bake long-lived credentials into images; use workload identity federation or injected short-lived tokens instead.' },
  { id: 'SP-030', title: 'Voice cloning / deepfake impersonation for social engineering', severity: 'High', cwe: 'CWE-451', description: 'An attacker uses AI-generated synthetic voice or video to impersonate an executive during a phone call or video conference to authorize a fraudulent action.', example: 'A deepfake voice call impersonating the CFO instructs finance staff to make an urgent wire transfer.', mitigation: 'Require out-of-band verification via a separate, pre-established channel for high-value or unusual requests.' },
  { id: 'SP-031', title: 'NTLM relay attack', severity: 'High', cwe: 'CWE-294', description: 'An attacker relays intercepted NTLM authentication attempts to a different service to authenticate as the victim without knowing their password.', example: 'A captured NTLM handshake from a print-spooler bug is relayed to authenticate against a domain controller.', mitigation: 'Disable NTLM in favor of Kerberos, enable SMB signing, and enforce Extended Protection for Authentication.' },
  { id: 'SP-032', title: 'Subdomain takeover enabling brand impersonation', severity: 'Medium', cwe: 'CWE-290', description: 'A DNS record points to a decommissioned third-party service (e.g., an unclaimed cloud storage bucket), allowing an attacker to claim it and serve content under the trusted domain.', example: 'An abandoned CNAME record pointing to a deleted cloud hosting endpoint is reclaimed by an attacker to host a phishing page on a trusted subdomain.', mitigation: 'Remove DNS records immediately when decommissioning third-party services and monitor for dangling CNAMEs.' },
  { id: 'SP-033', title: 'QR code phishing (quishing) redirecting to spoofed login', severity: 'Medium', cwe: 'CWE-1021', description: 'An attacker distributes a QR code that redirects victims to a spoofed login page, exploiting the difficulty of visually verifying a QR-encoded URL before scanning.', example: 'A QR code sticker placed over a legitimate parking payment sign redirects to a fake payment portal.', mitigation: 'Educate users to preview URLs before following QR codes and use branded, verifiable short-link domains.' },
  { id: 'SP-034', title: 'Golden ticket / forged Kerberos ticket', severity: 'Critical', cwe: 'CWE-294', description: 'An attacker who has compromised the Kerberos KRBTGT account hash can forge ticket-granting tickets to impersonate any user in the domain indefinitely.', example: 'An attacker with domain admin access extracts the KRBTGT hash and mints forged tickets months after the initial compromise is remediated.', mitigation: 'Rotate the KRBTGT account password twice after any suspected domain compromise and monitor for anomalous ticket lifetimes.' },
  { id: 'SP-035', title: 'Insecure "remember me" token enabling long-term impersonation', severity: 'Medium', cwe: 'CWE-539', description: 'A persistent "remember me" cookie uses a static, non-rotating token that, once stolen, grants indefinite impersonation of the user.', example: 'A stolen remember-me cookie continues to authenticate an attacker for months after the original theft.', mitigation: 'Use rotating, single-use remember-me tokens invalidated on use and tied to device fingerprints.' },
  { id: 'SP-036', title: 'Spoofed push notification triggering MFA fatigue approval', severity: 'High', cwe: 'CWE-287', description: 'An attacker who has valid credentials repeatedly triggers MFA push prompts, hoping the victim approves one out of annoyance or confusion (MFA fatigue / push bombing).', example: 'A user approves a push notification at 2 a.m. simply to make the repeated prompts stop, granting the attacker access.', mitigation: 'Use number-matching MFA challenges and rate-limit push notification attempts with automatic lockout on repeated denials.' },
  { id: 'SP-037', title: 'Impersonating a webhook sender without signature verification', severity: 'Medium', cwe: 'CWE-345', description: 'A system accepts inbound webhook calls without verifying an HMAC signature, allowing an attacker to send forged events appearing to originate from a trusted integration partner.', example: 'A forged payment-confirmed webhook is sent directly to the order fulfillment endpoint, triggering shipment without actual payment.', mitigation: 'Verify HMAC signatures and timestamps on every inbound webhook payload before processing.' },
  { id: 'SP-038', title: 'Content spoofing via unsanitized reflected parameters', severity: 'Low', cwe: 'CWE-451', description: 'User-controlled input is reflected into the page without encoding, allowing an attacker to inject fake content that appears to be part of the legitimate site.', example: 'A crafted URL injects a fake "your session has expired, re-enter your password" banner into the real page.', mitigation: 'Encode all reflected user input and apply a strict Content-Security-Policy.' },
  { id: 'SP-039', title: 'Man-in-the-middle on unauthenticated firmware update channel', severity: 'High', cwe: 'CWE-494', description: 'A device checks for and downloads firmware updates over an unauthenticated channel, allowing an attacker positioned on the network to impersonate the update server.', example: 'An attacker on the same network responds to a firmware update check with a malicious image before the real server can respond.', mitigation: 'Require TLS with certificate pinning and signed firmware images validated before installation.' },
  { id: 'SP-040', title: 'Business email compromise via mailbox rule injection', severity: 'High', cwe: 'CWE-290', description: 'After an initial account compromise, an attacker creates a hidden inbox rule to intercept and impersonate ongoing email conversations without detection.', example: 'A hidden rule forwards and deletes any email containing "invoice" so the attacker can respond as the compromised user.', mitigation: 'Monitor for anomalous mailbox rule creation and require MFA re-verification for mailbox rule changes.' },
  { id: 'SP-041', title: 'Impersonating a CI/CD pipeline via unauthenticated webhook trigger', severity: 'High', cwe: 'CWE-306', description: 'A build pipeline trigger endpoint accepts unauthenticated requests, allowing an attacker to impersonate a legitimate commit event and inject malicious build steps.', example: 'An attacker triggers a deployment pipeline with a forged payload pointing to an attacker-controlled branch.', mitigation: 'Require signed webhook payloads and authenticated triggers scoped to specific repositories and branches.' },
  { id: 'SP-042', title: 'Spoofed GPS signal misleading location-based access control', severity: 'Medium', cwe: 'CWE-290', description: 'An attacker broadcasts a fraudulent GPS signal to spoof the device\'s reported location, bypassing geofenced access controls.', example: 'A delivery driver app is spoofed to report a fake location to claim a delivery bonus tied to a specific zone.', mitigation: 'Cross-validate GPS with network-based location signals and flag physically implausible location jumps.' },
  { id: 'SP-043', title: 'Impersonation through shared API key across multiple partners', severity: 'Medium', cwe: 'CWE-798', description: 'A single API key is shared across multiple partner integrations, making it impossible to distinguish which partner is making a given call and enabling one partner to impersonate another if the key leaks.', example: 'A leaked shared key lets a malicious former partner continue making calls attributed to a still-active partner.', mitigation: 'Issue unique, individually revocable API keys per partner or integration.' },
  { id: 'SP-044', title: 'Rogue Bluetooth Low Energy beacon impersonating trusted proximity device', severity: 'Low', cwe: 'CWE-290', description: 'An attacker broadcasts a BLE beacon signal mimicking a trusted proximity-based access device (e.g., a keyless entry fob) to trigger unlock behavior.', example: 'A cloned BLE beacon signal unlocks a smart office door normally opened by an employee\'s badge fob.', mitigation: 'Use cryptographic challenge-response for proximity authentication instead of static beacon identifiers.' },
  { id: 'SP-045', title: 'Spoofed sender in Slack/Teams integration bot messages', severity: 'Low', cwe: 'CWE-290', description: 'A misconfigured chat integration allows any external caller to post messages appearing to come from a trusted internal bot, enabling social engineering within a trusted channel.', example: 'An attacker posts a fake "IT Security" bot message in a company Slack channel requesting password re-entry via a phishing link.', mitigation: 'Restrict incoming webhook tokens, verify request signing secrets, and label all bot-originated messages clearly.' },
];

/* ============================================================================
   SECTION 7: THREAT LIBRARY -- TAMPERING (45 threats)
   ========================================================================== */

const THREAT_LIBRARY_TAMPERING = [
  { id: 'TA-001', title: 'SQL injection modifying database records', severity: 'Critical', cwe: 'CWE-89', description: 'Unsanitized user input is concatenated into a SQL query, allowing an attacker to modify, delete, or read arbitrary database records.', example: 'A login field containing a crafted payload updates every user\'s role to administrator.', mitigation: 'Use parameterized queries or an ORM with built-in escaping; never concatenate user input into SQL strings.' },
  { id: 'TA-002', title: 'Client-side price/parameter tampering', severity: 'High', cwe: 'CWE-472', description: 'An attacker intercepts and modifies request parameters (price, discount, quantity) before submission, and the server trusts them without re-validation.', example: 'A modified request changes an item price from $100 to $1 before checkout.', mitigation: 'Re-derive and validate all security-relevant values server-side; never trust client-submitted totals.' },
  { id: 'TA-003', title: 'Software supply chain compromise via poisoned dependency', severity: 'Critical', cwe: 'CWE-829', description: 'An attacker publishes a malicious update to a widely used open-source package, which is pulled into production builds automatically.', example: 'A popular npm package is compromised and injects a credential-stealing payload into every downstream build.', mitigation: 'Pin dependency versions, verify checksums/signatures, and use a vetted internal package mirror with review gates.' },
  { id: 'TA-004', title: 'Man-in-the-middle modification of software update package', severity: 'Critical', cwe: 'CWE-494', description: 'An attacker intercepts an unsigned or unverified software update in transit and replaces it with a malicious payload.', example: 'An attacker on a shared network replaces a downloaded update installer with a backdoored version.', mitigation: 'Sign all update packages and verify signatures against a trusted public key before installation.' },
  { id: 'TA-005', title: 'Audit log tampering by a privileged insider', severity: 'High', cwe: 'CWE-117', description: 'A user with sufficient access modifies or deletes audit log entries to hide evidence of unauthorized activity.', example: 'A database administrator deletes rows from the audit table after performing an unauthorized data export.', mitigation: 'Ship logs immediately to an append-only, separately privileged system that the source account cannot write to.' },
  { id: 'TA-006', title: 'Firmware reflashing without signature verification', severity: 'Critical', cwe: 'CWE-347', description: 'A device accepts and installs firmware updates without verifying a cryptographic signature, allowing an attacker to install malicious firmware.', example: 'An attacker with physical or network access flashes a backdoored firmware image onto an IoT gateway.', mitigation: 'Implement secure boot and require signed firmware validated by a hardware root of trust.' },
  { id: 'TA-007', title: 'Cross-site scripting (stored) modifying page content for other users', severity: 'High', cwe: 'CWE-79', description: 'Unsanitized user input is stored and later rendered to other users without encoding, allowing an attacker to inject and execute arbitrary script content in victims\' browsers.', example: 'A malicious comment containing a script tag steals session cookies from every user who views the comment thread.', mitigation: 'Encode output based on context (HTML, JS, URL) and apply a strict Content-Security-Policy.' },
  { id: 'TA-008', title: 'Insecure direct file upload overwriting system files', severity: 'High', cwe: 'CWE-434', description: 'A file upload feature fails to validate the destination path, allowing an attacker to overwrite critical application or system files via path traversal.', example: 'An uploaded filename containing "../../" overwrites the application\'s configuration file.', mitigation: 'Generate server-side file names, store uploads outside the web root, and validate paths against traversal sequences.' },
  { id: 'TA-009', title: 'Configuration drift disabling security controls unnoticed', severity: 'Medium', cwe: 'CWE-668', description: 'A manual or unauthorized change to production configuration silently disables a security control, and no monitoring detects the drift.', example: 'A firewall rule temporarily opened for troubleshooting is never closed, remaining exposed for months.', mitigation: 'Use infrastructure-as-code with automated drift detection and alerting on unauthorized changes.' },
  { id: 'TA-010', title: 'Parameter pollution causing unexpected server-side behavior', severity: 'Medium', cwe: 'CWE-235', description: 'Duplicate HTTP parameters are interpreted differently by different components in the request chain, allowing an attacker to smuggle a conflicting value past validation.', example: 'A WAF validates the first instance of a parameter while the backend uses the last, allowing a malicious second value through.', mitigation: 'Use strict schema validation that rejects duplicate or unexpected parameters consistently across all layers.' },
  { id: 'TA-011', title: 'Insecure deserialization enabling object injection', severity: 'Critical', cwe: 'CWE-502', description: 'An application deserializes untrusted data without validation, allowing an attacker to construct malicious objects that execute code or alter application state.', example: 'A crafted serialized object triggers a gadget chain that executes arbitrary commands upon deserialization.', mitigation: 'Avoid native deserialization of untrusted input; use schema-validated formats like JSON with strict typing.' },
  { id: 'TA-012', title: 'Git commit history rewrite hiding malicious changes', severity: 'Medium', cwe: 'CWE-284', description: 'An attacker with write access to a source repository force-pushes a rewritten history to hide evidence of a malicious commit.', example: 'A force-push removes a suspicious commit from the visible history before it is discovered by code review.', mitigation: 'Enforce branch protection rules that disallow force-pushes and require signed, immutable commit history on protected branches.' },
  { id: 'TA-013', title: 'Tampering with mobile app local storage to unlock premium features', severity: 'Medium', cwe: 'CWE-602', description: 'An application enforces entitlement checks (e.g., premium status) using client-side local storage values that can be modified by the user.', example: 'A user edits a local SQLite database flag from "false" to "true" to unlock paid features without payment.', mitigation: 'Enforce entitlement checks server-side on every request that grants access to paid functionality.' },
  { id: 'TA-014', title: 'DOM-based tampering bypassing client-side validation logic', severity: 'Medium', cwe: 'CWE-602', description: 'An attacker uses browser developer tools or a proxy to bypass or modify client-side JavaScript validation before submission.', example: 'A disabled form field enforcing a maximum discount is re-enabled via developer tools and submitted with an arbitrary value.', mitigation: 'Treat all client-side validation as a UX convenience only; enforce identical rules server-side.' },
  { id: 'TA-015', title: 'Backup file tampering to reintroduce a compromised state', severity: 'High', cwe: 'CWE-345', description: 'An attacker with access to backup storage modifies a backup so that restoring it reintroduces a backdoor or compromised configuration.', example: 'A tampered backup restores an attacker-controlled admin account that was previously removed.', mitigation: 'Store backups in immutable, access-controlled storage with integrity hash verification before restore.' },
  { id: 'TA-016', title: 'Container image tampering after build, before deployment', severity: 'High', cwe: 'CWE-494', description: 'A container image is modified between the build pipeline and the deployment target, introducing malicious layers without detection.', example: 'An attacker with registry write access pushes a modified image tag pointing to a backdoored layer.', mitigation: 'Sign container images (e.g., cosign) and enforce admission control that rejects unsigned or unverified images.' },
  { id: 'TA-017', title: 'HTTP request smuggling altering downstream request interpretation', severity: 'High', cwe: 'CWE-444', description: 'Discrepancies in how a front-end proxy and back-end server parse Content-Length and Transfer-Encoding headers allow an attacker to smuggle a second, hidden request that tampers with another user\'s request.', example: 'A smuggled request injects malicious content into the next legitimate user\'s response.', mitigation: 'Normalize and reject ambiguous Content-Length/Transfer-Encoding header combinations at the edge proxy.' },
  { id: 'TA-018', title: 'Tampering with IoT sensor data before ingestion', severity: 'Medium', cwe: 'CWE-345', description: 'A sensor device transmits data over an unauthenticated channel, allowing an attacker to inject falsified readings into the ingestion pipeline.', example: 'Falsified temperature sensor data masks an actual equipment failure condition.', mitigation: 'Sign sensor payloads at the source and validate signatures at the ingestion service.' },
  { id: 'TA-019', title: 'Race condition tampering with financial transaction state', severity: 'High', cwe: 'CWE-362', description: 'Concurrent requests exploit a time-of-check-to-time-of-use gap to modify a balance or inventory count beyond intended limits.', example: 'Simultaneous withdrawal requests both pass a balance check before either debit is applied, resulting in an overdraft.', mitigation: 'Use atomic database transactions or optimistic locking to serialize state-changing operations.' },
  { id: 'TA-020', title: 'XML External Entity (XXE) injection modifying processed output', severity: 'High', cwe: 'CWE-611', description: 'An XML parser configured to resolve external entities allows an attacker to read local files or manipulate the processed document content.', example: 'A crafted XML payload includes an external entity that reads and injects the contents of a local configuration file.', mitigation: 'Disable external entity resolution and DTD processing in all XML parsers by default.' },
  { id: 'TA-021', title: 'Tampering with signed URLs by exploiting weak expiry validation', severity: 'Medium', cwe: 'CWE-347', description: 'A pre-signed URL\'s expiry or scope parameters can be manipulated because the signature does not cover all relevant fields.', example: 'An attacker modifies the expiry timestamp of a signed download URL to extend its validity indefinitely.', mitigation: 'Include every security-relevant parameter (expiry, scope, resource path) inside the signed payload itself.' },
  { id: 'TA-022', title: 'Prototype pollution altering application logic', severity: 'High', cwe: 'CWE-1321', description: 'An attacker injects properties into a JavaScript object\'s prototype chain via unsanitized merge/clone operations, altering application-wide behavior.', example: 'A crafted JSON payload sets Object.prototype.isAdmin = true, granting elevated behavior across the app.', mitigation: 'Use safe object merge libraries that block prototype-chain keys (__proto__, constructor, prototype).' },
  { id: 'TA-023', title: 'Malicious pull request injecting a CI/CD pipeline backdoor', severity: 'Critical', cwe: 'CWE-829', description: 'An attacker submits a pull request that modifies build scripts or CI configuration to exfiltrate secrets or inject malicious code during the build process.', example: 'A modified GitHub Actions workflow file exfiltrates repository secrets to an external endpoint during CI runs.', mitigation: 'Require manual approval for workflow file changes from external contributors and run CI with least-privilege tokens.' },
  { id: 'TA-024', title: 'Tampering with email content via HTML injection in transactional emails', severity: 'Low', cwe: 'CWE-79', description: 'User-controlled input is embedded into a transactional HTML email without sanitization, allowing an attacker to alter email appearance or embed malicious links.', example: 'A crafted display name injects a fake "verify your account" link into a legitimate notification email.', mitigation: 'Sanitize and encode all user-controlled content embedded into HTML email templates.' },
  { id: 'TA-025', title: 'Cache poisoning altering content served to other users', severity: 'High', cwe: 'CWE-444', description: 'An attacker manipulates unkeyed request inputs (headers, query parameters) that get cached, poisoning the cache with malicious content served to subsequent users.', example: 'A crafted X-Forwarded-Host header is reflected into a cached page and served to all subsequent visitors.', mitigation: 'Ensure cache keys include all inputs that influence the response, and strip untrusted headers before caching.' },
  { id: 'TA-026', title: 'Modifying feature flags to bypass business logic controls', severity: 'Medium', cwe: 'CWE-284', description: 'A feature flag or configuration service lacks access control, allowing an unauthorized party to toggle flags that disable security checks.', example: 'An attacker flips a feature flag that disables fraud-detection scoring on checkout.', mitigation: 'Apply the same access control and audit logging to feature-flag services as to production configuration.' },
  { id: 'TA-027', title: 'Tampering with mobile app binary via repackaging', severity: 'Medium', cwe: 'CWE-494', description: 'An attacker decompiles, modifies, and re-signs a mobile application with a different certificate, distributing a tampered version through unofficial channels.', example: 'A repackaged banking app with injected malware is distributed via a third-party app store.', mitigation: 'Implement runtime application self-protection (RASP), root/jailbreak detection, and integrity checks at startup.' },
  { id: 'TA-028', title: 'Log injection forging false audit trail entries', severity: 'Medium', cwe: 'CWE-117', description: 'Unsanitized user input containing newline or control characters is written directly into log files, allowing an attacker to forge fake log entries.', example: 'A crafted username containing embedded newlines fabricates a fake "admin login successful" log line.', mitigation: 'Sanitize or encode control characters before writing user input into log entries; use structured logging.' },
  { id: 'TA-029', title: 'GraphQL mutation abuse modifying unauthorized fields', severity: 'High', cwe: 'CWE-915', description: 'A GraphQL mutation binds directly to an internal model without field-level authorization, allowing an attacker to modify privileged fields not intended to be user-writable.', example: 'A mutation intended to update a display name also accepts and applies an "isAdmin" field.', mitigation: 'Use explicit input types with allow-listed writable fields rather than binding mutations directly to internal models.' },
  { id: 'TA-030', title: 'Tampering with time-series/IoT telemetry to hide equipment tampering', severity: 'Medium', cwe: 'CWE-345', description: 'An attacker replays or fabricates historical telemetry data to mask evidence of physical tampering with monitored equipment.', example: 'Replayed "normal" sensor readings mask an attacker physically disabling a security camera.', mitigation: 'Use signed, timestamped telemetry with anomaly detection for replayed or out-of-sequence data.' },
  { id: 'TA-031', title: 'Modifying URL query parameters to bypass access control checks', severity: 'Medium', cwe: 'CWE-639', description: 'An endpoint uses a client-supplied identifier without verifying the requester actually owns or is authorized for that resource.', example: 'Changing "?userId=1002" to "?userId=1003" in a profile URL displays another user\'s private data.', mitigation: 'Enforce object-level authorization checks server-side for every parameterized resource access.' },
  { id: 'TA-032', title: 'Tampering with DNS zone records via compromised registrar account', severity: 'Critical', cwe: 'CWE-284', description: 'An attacker who compromises a domain registrar account modifies DNS records to redirect traffic or intercept email.', example: 'MX records are changed to route all incoming email through an attacker-controlled mail server.', mitigation: 'Enable registrar-level MFA, registry lock, and monitor DNS record changes with alerting.' },
  { id: 'TA-033', title: 'Modifying HTTP response headers via reverse proxy misconfiguration', severity: 'Low', cwe: 'CWE-16', description: 'A misconfigured reverse proxy allows an attacker to inject or override security-relevant response headers.', example: 'An attacker-controlled request header is reflected into the response, overriding the Content-Security-Policy.', mitigation: 'Set security headers at a layer the client cannot influence, and validate proxy header-passthrough rules.' },
  { id: 'TA-034', title: 'Tampering with digital signatures via hash length extension attack', severity: 'High', cwe: 'CWE-347', description: 'A vulnerable hash-based MAC construction (e.g., naive MD5/SHA1 concatenation) allows an attacker to append data to a signed message while producing a valid signature.', example: 'An attacker extends a signed URL with additional parameters that pass signature verification due to a length-extension flaw.', mitigation: 'Use HMAC (not naive hash concatenation) for message authentication, and prefer SHA-256 or stronger.' },
  { id: 'TA-035', title: 'Tampering with package lockfile to introduce malicious transitive dependency', severity: 'High', cwe: 'CWE-829', description: 'An attacker modifies a lockfile to pin a transitive dependency to a malicious version while leaving the top-level manifest looking unchanged.', example: 'A pull request subtly alters a resolved version hash in package-lock.json to point to a compromised package release.', mitigation: 'Review lockfile diffs in code review and verify package integrity hashes against a trusted registry.' },
  { id: 'TA-036', title: 'Tampering with IoT device configuration via unauthenticated local API', severity: 'Medium', cwe: 'CWE-306', description: 'A local management API on an IoT device lacks authentication, allowing any device on the same network to alter its configuration.', example: 'An attacker on the home network changes a smart lock\'s configuration to accept an additional unauthorized key.', mitigation: 'Require authentication on all local management interfaces, even those assumed to be network-isolated.' },
  { id: 'TA-037', title: 'Modifying serialized session state stored client-side without integrity protection', severity: 'High', cwe: 'CWE-353', description: 'Session or state data is stored in a client-side cookie or token without a message authentication code, allowing an attacker to modify fields directly.', example: 'A cookie storing "role=user" in plaintext is edited to "role=admin" and accepted by the server.', mitigation: 'Sign or encrypt all client-stored state with a server-side secret and verify integrity on every read.' },
  { id: 'TA-038', title: 'Tampering with CSV/spreadsheet exports enabling formula injection', severity: 'Medium', cwe: 'CWE-1236', description: 'User-controlled input containing spreadsheet formula characters is exported into a CSV without sanitization, executing when opened in spreadsheet software.', example: 'A crafted "name" field beginning with "=cmd|\' /C calc\'!A1" executes a command when the export is opened in Excel.', mitigation: 'Prefix cells beginning with formula trigger characters with a neutralizing character before export.' },
  { id: 'TA-039', title: 'Tampering with load balancer health checks to mask a compromised host', severity: 'Medium', cwe: 'CWE-284', description: 'An attacker who has compromised a host manipulates its health check response to remain in the active pool, using it as a persistent foothold.', example: 'A compromised instance continues to report "healthy" while running a hidden malicious process.', mitigation: 'Use independent, out-of-band health verification and file integrity monitoring alongside standard health checks.' },
  { id: 'TA-040', title: 'Modifying infrastructure-as-code state file to hide unauthorized resources', severity: 'High', cwe: 'CWE-284', description: 'An attacker with access to a Terraform or similar state backend modifies the recorded state to hide manually created malicious resources from drift detection.', example: 'A rogue IAM user created outside of IaC is manually added to the state file to avoid triggering a destroy on the next apply.', mitigation: 'Store state in a locked, versioned, access-controlled backend and reconcile against live cloud inventory independently.' },
  { id: 'TA-041', title: 'Tampering with QR-code-based boarding pass or ticket data', severity: 'Medium', cwe: 'CWE-345', description: 'A QR code encoding ticket or boarding data lacks a digital signature, allowing an attacker to forge or modify entries such as seat class or validity date.', example: 'A modified QR-encoded ticket upgrades the seat class without payment.', mitigation: 'Digitally sign ticket payloads and validate the signature at every scan point, not just visually.' },
  { id: 'TA-042', title: 'Tampering with browser extension update mechanism', severity: 'High', cwe: 'CWE-494', description: 'A compromised or acquired browser extension pushes a malicious update through the legitimate auto-update channel, executing with the extension\'s existing broad permissions.', example: 'A previously benign extension is sold to a new owner who ships an update injecting ad-injection and credential-harvesting code.', mitigation: 'Monitor extension permission changes and enforce code review/signing requirements for extension update channels where possible.' },
  { id: 'TA-043', title: 'Tampering with API response caching at a shared CDN edge', severity: 'Medium', cwe: 'CWE-444', description: 'A CDN caches an API response containing user-specific data because cache-control headers are misconfigured, serving one user\'s tampered/mixed response to another.', example: 'A personalized account balance response is cached and served to a different user requesting the same URL shortly after.', mitigation: 'Set explicit no-store/private cache-control headers on any response containing user-specific data.' },
  { id: 'TA-044', title: 'Tampering with two-factor backup codes storage enabling bypass', severity: 'Medium', cwe: 'CWE-311', description: 'MFA backup/recovery codes are stored or transmitted without adequate protection, allowing an attacker to view or modify them and bypass the second factor.', example: 'Backup codes stored in plaintext in a support tool are viewed by a malicious insider to bypass a target account\'s MFA.', mitigation: 'Hash backup codes at rest like passwords and restrict access to authorized break-glass workflows only.' },
  { id: 'TA-045', title: 'Tampering with smart contract state via reentrancy exploitation', severity: 'Critical', cwe: 'CWE-841', description: 'A smart contract makes an external call before updating its internal state, allowing a malicious contract to re-enter and repeatedly tamper with balances before the state is finalized.', example: 'A reentrant call drains funds by repeatedly withdrawing before the balance is decremented.', mitigation: 'Follow the checks-effects-interactions pattern and use reentrancy guards on all state-changing external calls.' },
];

/* ============================================================================
   SECTION 8: THREAT LIBRARY -- REPUDIATION (42 threats)
   ========================================================================== */

const THREAT_LIBRARY_REPUDIATION = [
  { id: 'RE-001', title: 'Shared administrator account with no individual attribution', severity: 'High', cwe: 'CWE-284', description: 'Multiple administrators share a single privileged account, making it impossible to determine which individual performed a given action.', example: 'A production database is modified through a shared "dbadmin" account used by an entire team.', mitigation: 'Require individually attributable accounts with privilege elevation instead of shared credentials.' },
  { id: 'RE-002', title: 'Local-only logging destroyed by attacker after breach', severity: 'High', cwe: 'CWE-778', description: 'Logs are stored solely on the local host, allowing an attacker with sufficient access to delete or modify them to erase evidence of their activity.', example: 'An attacker deletes the local auth.log file after establishing persistence, leaving no record of initial access.', mitigation: 'Forward logs off-host in near real time to a system the compromised host cannot write to.' },
  { id: 'RE-003', title: 'Insufficient logging of security-relevant actions', severity: 'Medium', cwe: 'CWE-778', description: 'The application fails to log critical actions such as permission changes, data exports, or authentication events, leaving no evidence trail.', example: 'A bulk data export feature is not logged at all, so a data exfiltration incident cannot be traced to a specific user or time.', mitigation: 'Define and enforce a logging standard covering all security-relevant events with user, action, target, and timestamp.' },
  { id: 'RE-004', title: 'Lack of digital signatures on high-value financial transactions', severity: 'High', cwe: 'CWE-347', description: 'Financial transactions are authorized without a cryptographic signature binding the user\'s intent, allowing later denial of having authorized the transaction.', example: 'A disputed wire transfer cannot be proven to have been authorized by the account holder due to lack of signed confirmation.', mitigation: 'Require digital signatures or step-up MFA confirmation for high-value transactions, retained as evidence.' },
  { id: 'RE-005', title: 'Unsynchronized system clocks preventing log correlation', severity: 'Medium', cwe: 'CWE-367', description: 'Servers with drifting or unsynchronized clocks produce logs that cannot be reliably correlated across systems during an investigation.', example: 'Investigators cannot establish the true sequence of events across three servers whose clocks differ by several minutes.', mitigation: 'Enforce NTP synchronization across all hosts and monitor for clock drift exceeding a defined threshold.' },
  { id: 'RE-006', title: 'API calls not traceable to originating user or session', severity: 'Medium', cwe: 'CWE-778', description: 'Backend services log only that "an API call occurred" without capturing the authenticated identity or session context that triggered it.', example: 'A malicious data modification via an internal API cannot be attributed to any specific user account.', mitigation: 'Propagate authenticated identity and trace IDs through every downstream service call and include them in logs.' },
  { id: 'RE-007', title: 'Support tool access to customer data with no access logging', severity: 'High', cwe: 'CWE-778', description: 'An internal support or admin tool allows staff to view or modify customer data without generating an audit record of the access.', example: 'A support engineer browses a celebrity customer\'s private data with no log entry ever created.', mitigation: 'Log every access to customer data through internal tools, including read-only views, with the accessing employee\'s identity.' },
  { id: 'RE-008', title: 'Log tampering due to excessive write privileges on log storage', severity: 'High', cwe: 'CWE-732', description: 'Application service accounts are granted write and delete privileges on the same log storage they write to, allowing a compromised service to erase its own trail.', example: 'A compromised application server deletes its own CloudWatch log group after an attacker gains code execution.', mitigation: 'Grant append-only permissions to application accounts and restrict delete/modify rights to a separate security team role.' },
  { id: 'RE-009', title: 'Approval workflow without recorded approver identity', severity: 'Medium', cwe: 'CWE-778', description: 'A change-management or approval system records only that "approved" occurred, without a verifiable, non-forgeable record of who approved it.', example: 'A production deployment approval cannot be traced to a specific manager after a disputed incident.', mitigation: 'Bind approvals to authenticated identity with MFA-backed confirmation, stored immutably.' },
  { id: 'RE-010', title: 'Missing chain-of-custody documentation for forensic evidence', severity: 'Medium', cwe: 'CWE-778', description: 'Evidence collected during incident response lacks documentation of who collected it, when, and how it was preserved, undermining its usability in legal or disciplinary proceedings.', example: 'A disk image collected during an investigation is later challenged because no chain-of-custody log exists.', mitigation: 'Adopt formal forensic evidence-handling procedures with signed custody logs at every transfer.' },
  { id: 'RE-011', title: 'Deletable customer-facing receipts with no independent copy', severity: 'Low', cwe: 'CWE-778', description: 'Transaction receipts exist only within the user\'s own account view, and users can delete them, removing all evidence of the transaction.', example: 'A user deletes an order from their account history and then disputes ever having placed it.', mitigation: 'Generate independent, immutable transaction records (e.g., emailed confirmations) the user cannot unilaterally delete.' },
  { id: 'RE-012', title: 'Database changes made outside application logging (direct DB access)', severity: 'High', cwe: 'CWE-778', description: 'Privileged users with direct database access can modify records without triggering the application\'s audit logging layer.', example: 'A DBA directly updates a customer\'s account balance via a SQL client, bypassing all application-level audit logs.', mitigation: 'Enable database-native audit logging (e.g., triggers or native audit features) independent of the application layer.' },
  { id: 'RE-013', title: 'No session recording for privileged jump-host access', severity: 'Medium', cwe: 'CWE-778', description: 'Administrative sessions to sensitive systems are not recorded, leaving no record of specific commands executed during a privileged session.', example: 'A privileged session to a production database server executes destructive commands with no session transcript retained.', mitigation: 'Deploy session recording/keystroke logging on jump hosts and bastion access to critical systems.' },
  { id: 'RE-014', title: 'Anonymous or unauthenticated feedback/reporting channel abused for false claims', severity: 'Low', cwe: 'CWE-290', description: 'A feedback or reporting channel with no authentication allows a malicious actor to submit false reports while remaining unattributable and unaccountable.', example: 'An anonymous internal complaint system is repeatedly abused to submit fabricated harassment claims against a colleague.', mitigation: 'Balance legitimate anonymity needs with abuse controls such as rate limiting and pattern-based abuse detection.' },
  { id: 'RE-015', title: 'Log retention shorter than legal or regulatory requirement', severity: 'Medium', cwe: 'CWE-778', description: 'Logs are purged before the minimum retention period required by applicable law or contract, eliminating evidence needed for later investigation or audit.', example: 'Payment transaction logs are purged after 30 days despite a contractual 1-year retention requirement.', mitigation: 'Define retention periods per regulatory/contractual obligation and enforce them via automated lifecycle policies.' },
  { id: 'RE-016', title: 'Repudiation of email/message receipt due to lack of delivery confirmation', severity: 'Low', cwe: 'CWE-778', description: 'A notification or legal-communication system cannot prove a message was actually delivered and read, allowing a recipient to deny receipt.', example: 'A recipient denies receiving a legally required notice, and no delivery/read receipt evidence exists.', mitigation: 'Use delivery and read-receipt tracking, or certified messaging services, for legally significant communications.' },
  { id: 'RE-017', title: 'Insufficient logging of failed authentication attempts', severity: 'Medium', cwe: 'CWE-778', description: 'The system logs successful logins but not failed attempts, hiding evidence of brute-force or credential-stuffing activity and any resulting later compromise.', example: 'Thousands of failed login attempts preceding a successful breach are never recorded.', mitigation: 'Log both successful and failed authentication attempts with source IP, timestamp, and target account.' },
  { id: 'RE-018', title: 'Mutable audit trail in a spreadsheet-based change log', severity: 'Medium', cwe: 'CWE-284', description: 'Critical change records are tracked in an editable shared spreadsheet rather than an immutable system, allowing retroactive alteration.', example: 'A row documenting an unauthorized firewall change is quietly edited after the fact to show pre-approval.', mitigation: 'Replace manual spreadsheet change logs with a versioned, access-controlled change-management system.' },
  { id: 'RE-019', title: 'No non-repudiation mechanism for e-signatures on contracts', severity: 'Medium', cwe: 'CWE-347', description: 'An electronic signature workflow does not cryptographically bind the signer\'s identity and intent to the signed document, allowing later denial of signature.', example: 'A signer disputes having signed a contract, and the e-signature platform cannot produce cryptographic proof of intent.', mitigation: 'Use e-signature platforms that provide cryptographically verifiable signatures with identity verification and audit trails.' },
  { id: 'RE-020', title: 'Log forwarding silently fails without alerting', severity: 'Medium', cwe: 'CWE-778', description: 'A misconfiguration or outage silently stops log forwarding to the central SIEM, and no alert is generated for the resulting gap in coverage.', example: 'A syslog forwarder silently stops working for three weeks, during which a breach goes undetected and unlogged centrally.', mitigation: 'Monitor expected log volume/heartbeat per source and alert immediately on unexpected drops.' },
  { id: 'RE-021', title: 'Ambiguous "system" actor attribution for automated actions', severity: 'Low', cwe: 'CWE-778', description: 'Automated jobs or bots record actions under a generic "system" identity, making it impossible to distinguish legitimate automation from an attacker impersonating the automation.', example: 'A malicious scheduled job masquerades as routine "system" maintenance in the audit log.', mitigation: 'Give every automated process a unique service identity that is individually logged and monitored.' },
  { id: 'RE-022', title: 'No cryptographic timestamping of critical audit records', severity: 'Low', cwe: 'CWE-347', description: 'Audit logs lack a trusted timestamp mechanism, making it possible for an insider with system access to alter both content and timestamp undetected.', example: 'A backdated log entry is inserted to falsely establish an alibi for a specific time window.', mitigation: 'Use a trusted timestamping authority (RFC 3161) or hash-chained logs to make backdating detectable.' },
  { id: 'RE-023', title: 'Repudiation of API rate-limit bypass via rotating anonymous credentials', severity: 'Medium', cwe: 'CWE-778', description: 'An attacker automates the creation of many low-value accounts or free-tier API keys, making it impossible to attribute abusive traffic to a single accountable identity.', example: 'Thousands of disposable free-tier accounts are used to scrape data, with each individually staying under rate limits.', mitigation: 'Correlate accounts using device/behavioral fingerprinting and require identity verification for elevated usage tiers.' },
  { id: 'RE-024', title: 'No audit trail for infrastructure-as-code apply operations', severity: 'Medium', cwe: 'CWE-778', description: 'Infrastructure changes applied via CI/CD pipelines are not individually attributed to the human who triggered them, only to the service account.', example: 'A destructive Terraform apply cannot be traced back to the engineer who merged the triggering pull request.', mitigation: 'Correlate pipeline execution logs with the triggering commit author and require signed commits for infra changes.' },
  { id: 'RE-025', title: 'Repudiation via VPN split-tunneling hiding true traffic origin', severity: 'Low', cwe: 'CWE-778', description: 'Split-tunnel VPN configurations allow some traffic to bypass corporate logging entirely, letting a user deny responsibility for actions taken outside the tunnel.', example: 'An employee denies downloading a sensitive file because it was routed outside the monitored VPN tunnel.', mitigation: 'Restrict split-tunneling for sensitive roles or ensure equivalent logging coverage regardless of tunnel configuration.' },
  { id: 'RE-026', title: 'Deniable messaging protocol misapplied to compliance-relevant communications', severity: 'Medium', cwe: 'CWE-778', description: 'A messaging platform designed for deniability (ephemeral, unsigned messages) is used for communications that later require an auditable record for compliance purposes.', example: 'Trade approval discussions occur over an auto-deleting chat app, violating recordkeeping requirements.', mitigation: 'Mandate approved, retained communication channels for any regulatorily significant business discussion.' },
  { id: 'RE-027', title: 'Repudiation of consent due to unlogged consent-flow interactions', severity: 'Medium', cwe: 'CWE-778', description: 'A user\'s consent to data processing or terms of service is not recorded with sufficient detail (version, timestamp, IP) to prove it occurred.', example: 'A user disputes having consented to a specific privacy policy version, and no record specifies which version they saw.', mitigation: 'Log the specific policy version, timestamp, and mechanism of consent for every consent event.' },
  { id: 'RE-028', title: 'No immutable record of privileged role grants and revocations', severity: 'Medium', cwe: 'CWE-778', description: 'Role and permission changes are applied directly in an identity system without a durable log of who granted or revoked which privilege and when.', example: 'An unexplained admin grant is discovered during an audit with no record of who authorized it.', mitigation: 'Log every IAM role/permission change with the granting identity, target, and justification, retained centrally.' },
  { id: 'RE-029', title: 'Repudiation of code review approval due to auto-approval bot misuse', severity: 'Medium', cwe: 'CWE-284', description: 'A bot account is configured to auto-approve pull requests under certain conditions, and the resulting approval record cannot demonstrate genuine human review occurred.', example: 'A malicious change is auto-approved by a misconfigured bot, and the merge log falsely implies human sign-off.', mitigation: 'Require at least one verified human approval on protected branches, distinct from any automation account.' },
  { id: 'RE-030', title: 'No verifiable record of data subject deletion request fulfillment', severity: 'Medium', cwe: 'CWE-778', description: 'A privacy deletion request is processed without generating a verifiable record proving the data was actually deleted from all systems.', example: 'A regulator requests proof that a user\'s data was deleted per GDPR, and no audit trail exists to demonstrate completion.', mitigation: 'Generate and retain deletion-completion certificates covering every system that stored the data.' },
  { id: 'RE-031', title: 'Repudiation of physical access via tailgating with no badge log entry', severity: 'Low', cwe: 'CWE-778', description: 'A person enters a secure facility by tailgating an authorized badge holder, leaving no individual access log entry attributing their entry.', example: 'An unauthorized visitor tailgates into a data center, and the badge log shows only the legitimate employee\'s entry.', mitigation: 'Enforce anti-tailgating controls (mantraps, security guards) and reconcile badge-in counts with physical headcounts.' },
  { id: 'RE-032', title: 'Repudiation of automated trading/algorithmic decisions lacking decision logs', severity: 'High', cwe: 'CWE-778', description: 'An automated decision-making system (trading algorithm, fraud model) does not log the specific inputs and model version that led to a given decision, preventing after-the-fact accountability.', example: 'A disputed automated trade cannot be explained because the specific model version and input snapshot were not retained.', mitigation: 'Log model version, input features, and decision output for every automated high-stakes decision.' },
  { id: 'RE-033', title: 'No verifiable audit trail for privileged cloud console actions', severity: 'Medium', cwe: 'CWE-778', description: 'Cloud provider audit logging (e.g., CloudTrail, Activity Log) is not enabled or is scoped too narrowly to capture all console-based administrative actions.', example: 'A security group is opened to the internet via the console, but the change is never captured because logging was disabled in that region.', mitigation: 'Enable comprehensive, multi-region cloud audit logging with centralized aggregation and tamper protection.' },
  { id: 'RE-034', title: 'Repudiation risk from log field truncation losing critical context', severity: 'Low', cwe: 'CWE-778', description: 'Logging infrastructure truncates long field values, silently dropping the portion of a request or payload that would have provided attribution evidence.', example: 'A truncated log entry cuts off the actual malicious SQL payload, leaving investigators without the full picture.', mitigation: 'Configure logging pipelines with field size limits appropriate to forensic needs, or store full payloads separately.' },
  { id: 'RE-035', title: 'Repudiation due to log format inconsistency preventing automated correlation', severity: 'Low', cwe: 'CWE-778', description: 'Different services log the same type of event in incompatible formats, preventing automated tools from correlating a single user action across systems.', example: 'A user ID is logged as "uid" in one service and "user_id" in another, breaking automated cross-system correlation during an investigation.', mitigation: 'Adopt a structured, standardized logging schema across all services (e.g., a common event format).' },
  { id: 'RE-036', title: 'No accountability for actions performed via impersonation/support-login feature', severity: 'High', cwe: 'CWE-778', description: 'A "login as user" support feature does not clearly distinguish and log actions performed by support staff versus the actual user in shared audit trails.', example: 'A support agent\'s action while impersonating a customer appears in logs as if the customer performed it themselves.', mitigation: 'Tag every impersonated-session action with both the acting support identity and the target user identity distinctly.' },
  { id: 'RE-037', title: 'Repudiation of malicious insider action hidden among high log noise volume', severity: 'Medium', cwe: 'CWE-778', description: 'Excessive, unfiltered logging volume makes it practically infeasible to identify a specific malicious action, providing effective deniability through obscurity.', example: 'A malicious export event is buried among millions of routine read-log entries, never flagged or reviewed.', mitigation: 'Implement log analytics/SIEM correlation rules that surface high-risk actions distinctly from routine noise.' },
  { id: 'RE-038', title: 'No record retained of terms-of-service version accepted at signup', severity: 'Low', cwe: 'CWE-778', description: 'The system only stores that a user "accepted terms" without recording which specific version, preventing enforcement of version-specific obligations later.', example: 'A dispute arises over which arbitration clause applied, and no record shows which ToS version the user actually accepted.', mitigation: 'Store a reference to the specific document version and hash accepted at the time of consent.' },
  { id: 'RE-039', title: 'Repudiation of malicious script execution via unlogged interactive shell sessions', severity: 'Medium', cwe: 'CWE-778', description: 'Interactive shell access to production servers is permitted without full command-history logging, allowing a user to deny having executed a specific destructive command.', example: 'An engineer denies running a destructive cleanup script, and no shell history is centrally retained to confirm or refute the claim.', mitigation: 'Centralize and protect shell history logging (e.g., via bastion hosts with full session capture).' },
  { id: 'RE-040', title: 'Repudiation of vendor/contractor actions due to shared service credentials', severity: 'Medium', cwe: 'CWE-798', description: 'A third-party vendor is given a single shared credential for integration access, making it impossible to attribute a specific vendor employee\'s action.', example: 'A data leak traced to the vendor cannot be attributed to a specific vendor employee due to shared API credentials.', mitigation: 'Require vendors to use per-employee, individually attributable credentials for all access to your systems.' },
  { id: 'RE-041', title: 'No proof of message integrity for legally binding electronic notices', severity: 'Medium', cwe: 'CWE-347', description: 'Legally significant notices (e.g., termination, breach notification) are sent without any mechanism proving the content was not altered after sending.', example: 'A recipient claims the notice they received differed from what the sender asserts was sent, with no way to verify either claim.', mitigation: 'Hash and archive the exact content of legally significant communications at the time of sending.' },
  { id: 'RE-042', title: 'Repudiation of API abuse due to lack of per-client request signing', severity: 'Medium', cwe: 'CWE-778', description: 'API requests are authenticated only by a bearer token without per-request signing, so if the token is later disputed as stolen, individual requests cannot be cryptographically tied to the legitimate holder.', example: 'A customer disputes a series of API calls made with their token, and there is no way to prove or disprove they personally issued each one.', mitigation: 'Use request signing (e.g., HMAC over the request) in addition to bearer tokens for high-value API operations.' },
];

/* ============================================================================
   SECTION 9: THREAT LIBRARY -- INFORMATION DISCLOSURE (44 threats)
   ========================================================================== */

const THREAT_LIBRARY_INFO_DISCLOSURE = [
  { id: 'ID-001', title: 'Publicly readable cloud storage bucket', severity: 'Critical', cwe: 'CWE-284', description: 'An object storage bucket is misconfigured with public read access, exposing its contents to anyone who discovers or guesses the URL.', example: 'A misconfigured S3 bucket exposes millions of customer records to unauthenticated internet access.', mitigation: 'Default all storage buckets to private, use automated scanning for public ACLs, and require explicit justification for any public exception.' },
  { id: 'ID-002', title: 'Excessive data exposure in API responses', severity: 'High', cwe: 'CWE-213', description: 'An API returns the full internal data object rather than the specific fields the client actually needs, exposing sensitive fields to any caller with basic access.', example: 'A "get user profile" endpoint returns password hashes and internal risk scores alongside the display name.', mitigation: 'Apply response-shaping/DTOs and field-level authorization so only intended fields are ever serialized.' },
  { id: 'ID-003', title: 'Verbose error messages exposing stack traces', severity: 'Medium', cwe: 'CWE-209', description: 'Unhandled exceptions return full stack traces, file paths, and framework version information directly to the client.', example: 'A 500 error page reveals the exact ORM version and internal file path structure, aiding further attack.', mitigation: 'Return generic error messages to clients in production; log full detail only server-side.' },
  { id: 'ID-004', title: 'Username enumeration via response timing or message differences', severity: 'Medium', cwe: 'CWE-203', description: 'A login or password-reset form returns different responses (or timing) for valid versus invalid usernames, allowing an attacker to enumerate registered accounts.', example: 'A password-reset form says "email not found" for invalid accounts but "reset link sent" for valid ones.', mitigation: 'Return identical responses and timing regardless of whether the account exists.' },
  { id: 'ID-005', title: 'Secrets committed to source control history', severity: 'Critical', cwe: 'CWE-798', description: 'API keys, passwords, or certificates are committed to a repository and remain retrievable in git history even after later removal.', example: 'A database password committed two years ago is still recoverable via git log despite being removed from the current file.', mitigation: 'Use pre-commit secret scanning, rotate any exposed secret immediately, and treat repository history as permanently compromised once secrets are found.' },
  { id: 'ID-006', title: 'Sensitive data logged in plaintext', severity: 'High', cwe: 'CWE-532', description: 'Passwords, tokens, or PII are written to application logs in plaintext, where they may be accessed by anyone with log access, including third-party log aggregation vendors.', example: 'A debug log line prints the full request body, including a user\'s plaintext password on a failed login.', mitigation: 'Implement log scrubbing/redaction middleware for known sensitive field patterns before persistence.' },
  { id: 'ID-007', title: 'Unencrypted data at rest in database or backups', severity: 'High', cwe: 'CWE-311', description: 'Sensitive data is stored without encryption, meaning anyone who gains file-system or backup access can read it directly.', example: 'A stolen unencrypted database backup exposes all customer PII without any additional effort from the attacker.', mitigation: 'Enable encryption at rest for databases, backups, and any exported data snapshots, with keys managed separately via KMS.' },
  { id: 'ID-008', title: 'Mobile app storing tokens in unencrypted local storage', severity: 'High', cwe: 'CWE-312', description: 'A mobile application stores authentication tokens or sensitive data in plaintext shared preferences or files accessible to other apps on a rooted/jailbroken device.', example: 'A malicious app on the same device reads an authentication token from an unprotected SharedPreferences file.', mitigation: 'Use platform-provided secure storage (Keychain/Keystore) for tokens and sensitive data.' },
  { id: 'ID-009', title: 'Source maps deployed to production exposing original source code', severity: 'Medium', cwe: 'CWE-540', description: 'JavaScript source maps are deployed alongside minified production code, allowing anyone to reconstruct the full original, readable source.', example: 'An attacker downloads source maps to reveal internal API endpoints and business logic comments not intended for public view.', mitigation: 'Exclude source maps from production builds or restrict their access to authenticated internal users.' },
  { id: 'ID-010', title: 'GraphQL introspection enabled in production', severity: 'Medium', cwe: 'CWE-200', description: 'A production GraphQL API allows introspection queries, revealing the entire schema including fields, types, and mutations not intended for public documentation.', example: 'An attacker uses introspection to discover an undocumented "impersonateUser" mutation.', mitigation: 'Disable introspection in production and expose schema documentation only through a controlled developer portal.' },
  { id: 'ID-011', title: 'Directory listing enabled on web server', severity: 'Medium', cwe: 'CWE-548', description: 'A web server serves directory listings for folders without an index file, exposing the names and structure of files not meant to be publicly browsable.', example: 'Browsing to /backups/ on a production server lists every backup file by name and date.', mitigation: 'Disable directory listing at the web server configuration level and verify no sensitive files sit in public directories.' },
  { id: 'ID-012', title: 'Timing side-channel in password/secret comparison', severity: 'Medium', cwe: 'CWE-208', description: 'A password or token comparison uses a standard string comparison that returns early on the first mismatched character, allowing an attacker to infer correct characters via response timing.', example: 'Statistical timing analysis of API key comparisons allows incremental guessing of the correct key.', mitigation: 'Use constant-time comparison functions for all secret and credential comparisons.' },
  { id: 'ID-013', title: 'Third-party analytics SDK over-collecting user data', severity: 'Medium', cwe: 'CWE-359', description: 'An embedded analytics or advertising SDK captures more data than intended, including form input, precise location, or device identifiers, and transmits it to a third party.', example: 'An analytics SDK\'s "session replay" feature inadvertently captures credit card numbers typed into a checkout form.', mitigation: 'Audit and configure third-party SDKs to mask sensitive fields and limit data collection scope.' },
  { id: 'ID-014', title: 'Unrestricted access to internal admin panel from the internet', severity: 'High', cwe: 'CWE-284', description: 'An administrative interface intended for internal use only is reachable from the public internet due to missing network restrictions.', example: 'A phpMyAdmin instance is discovered exposed directly to the internet via a search engine for internet-connected devices.', mitigation: 'Restrict admin interfaces to internal networks or VPN, with additional authentication layered on top.' },
  { id: 'ID-015', title: 'Sensitive metadata embedded in exported documents', severity: 'Low', cwe: 'CWE-200', description: 'Exported PDFs, spreadsheets, or images retain hidden metadata such as author names, internal file paths, or edit history revealing sensitive context.', example: 'A publicly shared PDF report retains "author: internal-legal-review-draft" in its metadata, revealing an unpublished internal process.', mitigation: 'Sanitize export pipelines to strip metadata before documents leave the organization.' },
  { id: 'ID-016', title: 'HTTP response headers revealing framework/server version', severity: 'Low', cwe: 'CWE-200', description: 'Default server or framework headers announce specific software versions, helping attackers target known vulnerabilities for that exact version.', example: 'A "Server: Apache/2.4.29" header lets an attacker immediately check for known CVEs affecting that specific version.', mitigation: 'Strip or generalize version-revealing headers at the reverse proxy/edge layer.' },
  { id: 'ID-017', title: 'Overly permissive CORS configuration leaking cross-origin data', severity: 'High', cwe: 'CWE-346', description: 'An API sets Access-Control-Allow-Origin to a wildcard or reflects any origin while also allowing credentials, letting any website read authenticated responses on behalf of a visiting user.', example: 'A malicious website silently reads a logged-in user\'s account data via a cross-origin fetch permitted by an overly broad CORS policy.', mitigation: 'Use an explicit allow-list of trusted origins and never combine wildcard origins with credentialed requests.' },
  { id: 'ID-018', title: 'Cache exposing sensitive data to subsequent unauthorized users', severity: 'High', cwe: 'CWE-524', description: 'Pages containing personalized or sensitive data are cached by a shared proxy or browser cache without appropriate cache-control directives, exposing them to the next user of a shared machine or proxy.', example: 'A logged-out shared library computer displays the previous user\'s cached account dashboard when the back button is pressed.', mitigation: 'Set Cache-Control: no-store on all pages and API responses containing sensitive or personalized data.' },
  { id: 'ID-019', title: 'Insecure direct object reference exposing another user\'s data', severity: 'High', cwe: 'CWE-639', description: 'An endpoint returns data based solely on a client-supplied identifier without verifying the requester is authorized to view that specific resource.', example: 'Changing the invoice ID in a URL displays another customer\'s full invoice details.', mitigation: 'Enforce object-level authorization checks on every request that accepts a resource identifier.' },
  { id: 'ID-020', title: 'Unmasked sensitive data displayed in internal support tools', severity: 'Medium', cwe: 'CWE-200', description: 'Internal customer-support tooling displays full, unmasked sensitive data (SSNs, full card numbers) to every support agent regardless of actual need.', example: 'A support agent handling a shipping question can view a customer\'s full unmasked payment card number.', mitigation: 'Apply role-based field masking in internal tools, revealing full values only when specifically justified and logged.' },
  { id: 'ID-021', title: 'DNS zone transfer allowed to unauthorized hosts', severity: 'Medium', cwe: 'CWE-200', description: 'A DNS server permits zone transfers (AXFR) to any requester, revealing the complete internal DNS record structure of the organization.', example: 'An attacker performs an AXFR query and receives a full list of internal hostnames, revealing the network topology.', mitigation: 'Restrict zone transfers to explicitly authorized secondary DNS servers only.' },
  { id: 'ID-022', title: 'Sensitive data exposure via search engine indexing', severity: 'Medium', cwe: 'CWE-200', description: 'Pages containing sensitive information are inadvertently crawled and indexed by search engines because they lack a robots.txt exclusion or noindex directive.', example: 'A "private" internal wiki page containing credentials appears in public search engine results.', mitigation: 'Apply noindex meta tags and robots.txt restrictions to any non-public content, and require authentication as the primary control.' },
  { id: 'ID-023', title: 'Password reset flow revealing whether an account is locked or disabled', severity: 'Low', cwe: 'CWE-203', description: 'A password reset or login flow returns account-status-specific messages (locked, disabled, unverified) that leak metadata about the target account to an attacker.', example: 'A distinct "account locked" message allows an attacker to identify targets for account-lockout denial-of-service attacks.', mitigation: 'Use a single generic response for all account states during authentication-adjacent flows.' },
  { id: 'ID-024', title: 'Leaking internal IP addresses or hostnames in client-facing error responses', severity: 'Low', cwe: 'CWE-200', description: 'Error responses expose internal network topology details such as private IP addresses or internal hostnames, aiding attacker reconnaissance.', example: 'A gateway timeout error reveals the internal hostname of the backend service that failed to respond.', mitigation: 'Sanitize all client-facing error messages to remove internal infrastructure details.' },
  { id: 'ID-025', title: 'Exposed .git or .env configuration directory on production web server', severity: 'Critical', cwe: 'CWE-538', description: 'The build or deployment process leaves version-control metadata or environment configuration files accessible under the web root.', example: 'A publicly accessible /.git/config file allows an attacker to reconstruct the entire source repository including embedded secrets.', mitigation: 'Exclude .git, .env, and other configuration/metadata directories from the deployed web root entirely.' },
  { id: 'ID-026', title: 'Cross-tenant data leakage in multi-tenant SaaS application', severity: 'Critical', cwe: 'CWE-668', description: 'A query or cache key fails to properly scope by tenant ID, allowing one customer to view another customer\'s data in a shared multi-tenant system.', example: 'A caching layer keys responses only by resource ID, not tenant ID, briefly serving one tenant\'s data to another.', mitigation: 'Enforce tenant-scoping at the data-access layer for every query and cache key, verified via automated tests.' },
  { id: 'ID-027', title: 'Overly detailed API rate-limit headers revealing internal architecture', severity: 'Low', cwe: 'CWE-200', description: 'Rate-limiting response headers expose internal implementation details such as specific backend service names or internal quota tiers.', example: 'A rate-limit header reveals the exact internal service name handling the request, aiding targeted attacks.', mitigation: 'Keep rate-limit header content generic and free of internal implementation identifiers.' },
  { id: 'ID-028', title: 'Publicly accessible API documentation revealing internal-only endpoints', severity: 'Medium', cwe: 'CWE-200', description: 'Auto-generated API documentation (e.g., Swagger/OpenAPI UI) is deployed publicly and includes internal-only or deprecated endpoints not intended for external use.', example: 'A public Swagger UI reveals an undocumented "/internal/debug/dump-db" endpoint.', mitigation: 'Restrict API documentation UIs to authenticated internal users and separate internal from external API specs.' },
  { id: 'ID-029', title: 'Sensitive information disclosed through HTTP OPTIONS/TRACE methods', severity: 'Low', cwe: 'CWE-200', description: 'Enabled HTTP TRACE or verbose OPTIONS responses can reveal request-handling internals or be leveraged in cross-site tracing attacks.', example: 'An enabled TRACE method reflects request headers back, aiding an XST-based cookie theft technique.', mitigation: 'Disable unnecessary HTTP methods (TRACE, TRACK) at the web server level.' },
  { id: 'ID-030', title: 'Third-party breach exposing data shared via integration partner', severity: 'High', cwe: 'CWE-200', description: 'Data shared with a third-party integration partner is exposed when that partner suffers its own security breach, outside the organization\'s direct control.', example: 'A marketing analytics partner is breached, exposing customer email addresses shared for campaign tracking.', mitigation: 'Minimize data shared with partners, require contractual security obligations, and monitor partner breach disclosures.' },
  { id: 'ID-031', title: 'Sensitive fields exposed in URL query strings, logged by proxies', severity: 'Medium', cwe: 'CWE-598', description: 'Sensitive data such as session tokens or PII is passed via GET query parameters, which are commonly logged by proxies, browsers, and referrer headers.', example: 'A password reset token in a URL query string is logged by an intermediate CDN and later leaked via referrer headers to a third-party analytics tag.', mitigation: 'Pass sensitive data via POST body or headers, never in URL query strings, especially GET.' },
  { id: 'ID-032', title: 'Weak or absent encryption of data in transit between internal services', severity: 'Medium', cwe: 'CWE-319', description: 'Internal service-to-service communication occurs over plaintext HTTP because it is assumed to be "trusted internal network", exposing data to anyone who gains a network foothold.', example: 'An attacker who compromises one internal host can sniff plaintext internal API traffic containing customer PII.', mitigation: 'Encrypt all internal service traffic with TLS/mTLS regardless of perceived network trust level.' },
  { id: 'ID-033', title: 'Sensitive push notification content displayed on locked device screen', severity: 'Low', cwe: 'CWE-200', description: 'A mobile push notification displays sensitive content (e.g., a one-time passcode or account balance) directly on the lock screen, visible to anyone with physical proximity to the device.', example: 'A 2FA code is fully visible on the lock screen notification, allowing a nearby observer to read it.', mitigation: 'Send generic notification text and require the app to be unlocked to reveal sensitive content.' },
  { id: 'ID-034', title: 'Publicly exposed Kubernetes dashboard without authentication', severity: 'Critical', cwe: 'CWE-306', description: 'A Kubernetes dashboard or API server is exposed to the internet without authentication, revealing cluster secrets, configuration, and workload details.', example: 'An internet-exposed Kubernetes dashboard allows any visitor to view all secrets stored in the cluster.', mitigation: 'Restrict dashboard and API server access to authenticated, network-isolated administrators only.' },
  { id: 'ID-035', title: 'Sensitive data exposed via unauthenticated GraphQL batch query abuse', severity: 'Medium', cwe: 'CWE-200', description: 'A GraphQL API allows unauthenticated or under-authorized batched queries that aggregate data across many records not intended to be bulk-accessible.', example: 'A single batched query retrieves profile data for thousands of user IDs sequentially, effectively scraping the entire user base.', mitigation: 'Apply query complexity limits, depth limits, and per-field authorization independent of query batching.' },
  { id: 'ID-036', title: 'Exposed .well-known or config endpoints leaking internal secrets', severity: 'Medium', cwe: 'CWE-200', description: 'Framework-generated diagnostic or configuration endpoints (e.g., actuator/env, phpinfo) are left enabled in production, revealing environment variables and secrets.', example: 'A Spring Boot Actuator /env endpoint exposes database credentials directly in the response.', mitigation: 'Disable or authenticate diagnostic and configuration endpoints before deploying to production.' },
  { id: 'ID-037', title: 'Data leakage through browser autofill on shared or public devices', severity: 'Low', cwe: 'CWE-200', description: 'A web form allows browser autofill of sensitive fields without appropriate autocomplete restrictions, risking exposure on shared or public computers.', example: 'A shared kiosk browser autofills a previous user\'s saved address and partial payment information.', mitigation: 'Set autocomplete="off" or appropriate restrictions on highly sensitive form fields where warranted.' },
  { id: 'ID-038', title: 'Exposed internal Slack/chat webhook URLs leaking notification content', severity: 'Medium', cwe: 'CWE-200', description: 'A webhook URL used to post notifications to an internal chat channel is exposed in client-side code or public repositories, allowing anyone to both read notification content patterns and post forged messages.', example: 'A hard-coded Slack webhook URL in a public repo lets an attacker flood a security team\'s alert channel with noise.', mitigation: 'Treat webhook URLs as secrets, store them in a secrets manager, and rotate any that are exposed.' },
  { id: 'ID-039', title: 'Sensitive data retained beyond necessity in application caches', severity: 'Medium', cwe: 'CWE-200', description: 'An in-memory or distributed cache retains sensitive data far longer than needed, increasing the window during which a cache compromise exposes it.', example: 'A Redis cache retains full session payloads including PII for 30 days when the actual session lifetime is 1 hour.', mitigation: 'Set cache TTLs aligned to actual data-freshness needs and avoid caching sensitive data beyond necessity.' },
  { id: 'ID-040', title: 'Unencrypted email transmission of sensitive account information', severity: 'Medium', cwe: 'CWE-319', description: 'Account statements, password reset links, or other sensitive data are sent via standard email without additional protection, and email is inherently susceptible to interception at various hops.', example: 'A full account statement including partial account numbers is emailed in plaintext with no additional protection.', mitigation: 'Minimize sensitive data in email bodies; direct users to a secure authenticated portal for full sensitive details instead.' },
  { id: 'ID-041', title: 'Information disclosure via HTTP response status code differences in access control checks', severity: 'Low', cwe: 'CWE-203', description: 'An API returns 404 for non-existent resources but 403 for resources that exist but are forbidden, allowing an attacker to enumerate valid resource IDs even without access.', example: 'Systematically probing IDs reveals which ones exist (403) versus do not exist (404), mapping the private resource space.', mitigation: 'Return a consistent, generic response (e.g., 404) for both non-existent and unauthorized resources.' },
  { id: 'ID-042', title: 'Sensitive configuration exposed via client-side JavaScript bundle', severity: 'High', cwe: 'CWE-200', description: 'Server-side configuration values, including API keys intended to be secret, are inadvertently bundled into client-side JavaScript during the build process.', example: 'A build script accidentally inlines a server-only Stripe secret key into the public JavaScript bundle.', mitigation: 'Separate build-time environment variables strictly into public (client-safe) and private (server-only) categories with tooling enforcement.' },
  { id: 'ID-043', title: 'Data disclosure via improperly scoped OAuth consent screen', severity: 'Medium', cwe: 'CWE-200', description: 'An OAuth application requests broader scopes than it needs, and users grant blanket access, exposing more of their data to the third-party application than necessary.', example: 'A simple calendar-viewing app requests full read/write access to email, contacts, and drive files.', mitigation: 'Request the minimum necessary OAuth scopes and use incremental authorization for optional features.' },
  { id: 'ID-044', title: 'Sensitive data exposure through unredacted screen-sharing during support sessions', severity: 'Low', cwe: 'CWE-200', description: 'Remote support or screen-sharing tooling exposes the full screen, including unrelated sensitive data visible in other open windows or notifications, during a support session.', example: 'A support session screen-share inadvertently displays an open password manager window in the background.', mitigation: 'Use application-window-only sharing and train staff to close unrelated sensitive windows before support sessions.' },
];

/* ============================================================================
   SECTION 10: THREAT LIBRARY -- DENIAL OF SERVICE (42 threats)
   ========================================================================== */

const THREAT_LIBRARY_DOS = [
  { id: 'DO-001', title: 'Volumetric DDoS flooding network bandwidth', severity: 'High', cwe: 'CWE-400', description: 'A botnet or amplification network floods the target\'s network link with junk traffic, exhausting available bandwidth and blocking legitimate requests.', example: 'A 500 Gbps UDP flood saturates the origin server\'s upstream network link entirely.', mitigation: 'Deploy DDoS scrubbing services, anycast networks, and CDN fronting for all internet-facing infrastructure.' },
  { id: 'DO-002', title: 'Application-layer HTTP flood exhausting server resources', severity: 'High', cwe: 'CWE-400', description: 'An attacker sends a high volume of seemingly legitimate HTTP requests targeting expensive endpoints, exhausting server CPU or database connections rather than raw bandwidth.', example: 'A flood of search requests against an unindexed database column exhausts all available database connections.', mitigation: 'Apply per-user/IP rate limiting, request queuing, and caching for expensive read operations.' },
  { id: 'DO-003', title: 'Regular expression denial of service (ReDoS)', severity: 'High', cwe: 'CWE-1333', description: 'A regular expression with nested quantifiers exhibits catastrophic backtracking on a crafted input, consuming CPU exponentially relative to input length.', example: 'A single crafted email-validation input string causes a worker thread to hang at 100% CPU for hours.', mitigation: 'Audit regexes for nested quantifiers, use regex engines with backtracking limits, or apply input length caps before matching.' },
  { id: 'DO-004', title: 'XML billion laughs / entity expansion attack', severity: 'High', cwe: 'CWE-776', description: 'A crafted XML document uses nested entity references that expand exponentially during parsing, exhausting memory.', example: 'A 1KB XML payload expands to gigabytes in memory once fully parsed, crashing the parsing service.', mitigation: 'Disable external entity and DTD processing, and enforce entity expansion limits in the XML parser.' },
  { id: 'DO-005', title: 'Unbounded file upload exhausting disk space', severity: 'Medium', cwe: 'CWE-400', description: 'A file upload feature does not enforce size or rate limits, allowing an attacker to repeatedly upload large files until storage is exhausted.', example: 'Repeated 2GB uploads from a single account fill the shared storage volume, causing outages for all tenants.', mitigation: 'Enforce per-file size limits, per-user storage quotas, and upload rate limiting server-side.' },
  { id: 'DO-006', title: 'Account lockout policy weaponized against legitimate users', severity: 'Medium', cwe: 'CWE-645', description: 'An attacker deliberately submits failed login attempts for a known username to trigger the account lockout policy, denying the legitimate user access.', example: 'An attacker locks out a competitor\'s sales team accounts before a critical demo by submitting repeated failed logins.', mitigation: 'Use progressive delays or risk-based throttling instead of hard account lockouts triggered by IP-independent attempts.' },
  { id: 'DO-007', title: 'Slowloris-style connection exhaustion attack', severity: 'Medium', cwe: 'CWE-400', description: 'An attacker opens many connections and sends data extremely slowly, keeping connections open and exhausting the server\'s available connection pool.', example: 'A few hundred slow, partial HTTP requests exhaust the web server\'s worker thread pool, blocking new legitimate connections.', mitigation: 'Configure aggressive idle and header-completion timeouts, and use a reverse proxy designed to mitigate slow-request attacks.' },
  { id: 'DO-008', title: 'DNS amplification attack using the target\'s own infrastructure', severity: 'High', cwe: 'CWE-406', description: 'An attacker spoofs the victim\'s IP address in small DNS queries sent to open resolvers, which respond with much larger replies directed at the victim, amplifying attack volume.', example: 'A 60-byte spoofed query triggers a 4000-byte response directed at the victim, amplifying attack traffic 60x.', mitigation: 'Disable open DNS resolvers, and rate-limit response sizes; use anycast/scrubbing for internet-facing DNS.' },
  { id: 'DO-009', title: 'Resource exhaustion via unbounded background job queue growth', severity: 'Medium', cwe: 'CWE-400', description: 'An attacker triggers a high volume of background job submissions (e.g., report generation, email sends) faster than they can be processed, growing the queue unboundedly and delaying all jobs.', example: 'Thousands of triggered report-generation jobs delay all legitimate email notifications by hours.', mitigation: 'Apply per-tenant queue quotas, priority lanes, and backpressure mechanisms on job submission endpoints.' },
  { id: 'DO-010', title: 'WebSocket connection exhaustion', severity: 'Medium', cwe: 'CWE-400', description: 'An attacker opens an excessive number of long-lived WebSocket connections from a small number of clients, exhausting the server\'s connection capacity for legitimate users.', example: 'A script opens 50,000 idle WebSocket connections from a handful of IPs, exhausting the server\'s file descriptor limit.', mitigation: 'Enforce maximum concurrent connections per identity/IP and reclaim idle connections aggressively.' },
  { id: 'DO-011', title: 'Algorithmic complexity attack via crafted hash collisions', severity: 'Medium', cwe: 'CWE-407', description: 'An attacker submits input specifically crafted to cause hash-table collisions in the server\'s data structures, degrading O(1) operations to O(n) and consuming excessive CPU.', example: 'A crafted set of form field names causes a hash table used for parameter parsing to degrade to linked-list performance, spiking CPU.', mitigation: 'Use hash functions with randomized seeds (e.g., SipHash) to prevent predictable collision crafting.' },
  { id: 'DO-012', title: 'Reflected amplification via NTP monlist command', severity: 'High', cwe: 'CWE-406', description: 'Outdated NTP servers supporting the "monlist" command can be abused to reflect and amplify traffic toward a spoofed victim IP address.', example: 'A small monlist request generates a response amplified by over 200x, directed at the victim.', mitigation: 'Disable monlist and other legacy NTP query commands; keep NTP daemons patched and updated.' },
  { id: 'DO-013', title: 'Compute-cost denial of service via autoscaling abuse', severity: 'Medium', cwe: 'CWE-400', description: 'An attacker generates sustained legitimate-looking load specifically to trigger costly autoscaling, resulting in a large unexpected cloud bill (economic denial of sustainability).', example: 'Sustained scraping traffic triggers autoscaling to hundreds of instances overnight, generating a massive unexpected invoice.', mitigation: 'Set autoscaling upper bounds, cost alerts, and anomaly-based traffic filtering ahead of scaling decisions.' },
  { id: 'DO-014', title: 'Denial of service via expensive third-party API pass-through', severity: 'Medium', cwe: 'CWE-400', description: 'An endpoint proxies requests to a costly or rate-limited third-party API without its own rate limiting, allowing an attacker to exhaust the shared third-party quota for all users.', example: 'Repeated calls to a proxy endpoint exhaust the organization\'s entire monthly geocoding API quota within an hour.', mitigation: 'Apply independent rate limiting and caching on any endpoint that proxies to a metered or rate-limited external API.' },
  { id: 'DO-015', title: 'Fork bomb / process exhaustion via malicious plugin or script execution', severity: 'High', cwe: 'CWE-400', description: 'A system that allows execution of user-supplied scripts or plugins is exposed to unbounded process creation, exhausting the host\'s process table and crashing the system for all tenants.', example: 'A crafted plugin spawns an unbounded number of subprocesses, exhausting the shared execution host.', mitigation: 'Sandbox untrusted code execution with strict process, memory, and CPU limits (cgroups/containers).' },
  { id: 'DO-016', title: 'Denial of service through unpaginated bulk data export requests', severity: 'Medium', cwe: 'CWE-400', description: 'An export or reporting feature allows requesting an unbounded amount of data in a single request, and repeated requests overwhelm database and memory resources.', example: 'A "export all records" endpoint with no size cap is repeatedly invoked, exhausting server memory generating massive CSV files.', mitigation: 'Enforce mandatory pagination limits and asynchronous job-based processing for large exports.' },
  { id: 'DO-017', title: 'SYN flood attack exhausting connection backlog', severity: 'Medium', cwe: 'CWE-400', description: 'An attacker sends a high volume of TCP SYN packets without completing the handshake, filling the server\'s half-open connection backlog.', example: 'A sustained SYN flood prevents any new legitimate TCP connections from being established.', mitigation: 'Enable SYN cookies and connection rate limiting at the network/load-balancer layer.' },
  { id: 'DO-018', title: 'Denial of service via malicious deeply nested JSON payload', severity: 'Medium', cwe: 'CWE-776', description: 'A JSON parser without depth limits recursively processes a deeply nested payload, causing stack exhaustion or excessive CPU consumption.', example: 'A JSON payload nested 100,000 levels deep crashes the parsing worker with a stack overflow.', mitigation: 'Enforce maximum nesting depth and payload size limits before or during JSON parsing.' },
  { id: 'DO-019', title: 'Certificate/TLS handshake flood exhausting CPU on cryptographic operations', severity: 'Medium', cwe: 'CWE-400', description: 'An attacker initiates a high volume of TLS handshakes without completing the session, exhausting server CPU dedicated to expensive asymmetric cryptographic operations.', example: 'Repeated TLS handshake initiation without completion drives CPU usage on the load balancer to 100%.', mitigation: 'Offload TLS termination to hardware-accelerated appliances or CDN edge, with handshake rate limiting.' },
  { id: 'DO-020', title: 'Denial of service via malicious regular expression in WAF bypass attempt', severity: 'Low', cwe: 'CWE-1333', description: 'An attacker probes for and exploits inefficient regex-based rules within a Web Application Firewall itself, causing the WAF to become the resource bottleneck.', example: 'A crafted payload causes the WAF\'s own inspection engine to hang, effectively taking down traffic inspection for all requests behind it.', mitigation: 'Choose WAF vendors with regex backtracking protections and monitor WAF resource utilization independently.' },
  { id: 'DO-021', title: 'Denial of service via cache-busting query parameter abuse', severity: 'Medium', cwe: 'CWE-400', description: 'An attacker appends unique, random query parameters to every request, bypassing CDN/cache layers and forcing every request to hit the origin server directly.', example: 'A flood of requests with random cache-busting query strings bypasses the CDN entirely, overwhelming the origin.', mitigation: 'Normalize or strip unrecognized query parameters before cache-key generation and origin routing.' },
  { id: 'DO-022', title: 'Denial of service via malicious image/media decompression bomb', severity: 'Medium', cwe: 'CWE-409', description: 'A small, highly compressed image or archive file expands to an enormous size upon decompression, exhausting memory or disk during processing.', example: 'A 500KB uploaded "image" decompresses to 10GB in memory when processed by a thumbnail generator, crashing the worker.', mitigation: 'Enforce decompressed-size limits and use streaming decompression with hard caps rather than full in-memory expansion.' },
  { id: 'DO-023', title: 'Denial of service via excessive password-hashing cost exploitation', severity: 'Low', cwe: 'CWE-400', description: 'An attacker submits a high volume of login attempts specifically to trigger the computationally expensive password-hashing (bcrypt/argon2) operation, exhausting CPU.', example: 'A flood of login attempts against valid usernames consumes all available CPU on expensive bcrypt hashing.', mitigation: 'Rate-limit login attempts before the expensive hashing step and consider hardware-accelerated hashing where appropriate.' },
  { id: 'DO-024', title: 'Denial of service via mail server relay abuse', severity: 'Medium', cwe: 'CWE-400', description: 'An open or poorly rate-limited email-sending feature is abused to send massive volumes of email, exhausting sending reputation and provider quota, effectively denying legitimate email delivery.', example: 'An attacker abuses a "forgot password" email trigger to spam a target inbox thousands of times, and the sending domain gets blacklisted.', mitigation: 'Rate-limit outbound transactional email per recipient and per triggering account.' },
  { id: 'DO-025', title: 'Denial of service via GraphQL query complexity/depth abuse', severity: 'High', cwe: 'CWE-400', description: 'A GraphQL API without query cost analysis allows a deeply nested or highly complex query to trigger an enormous number of resolver calls, exhausting backend resources with a single request.', example: 'A single deeply nested query triggers millions of database calls through nested relational resolvers.', mitigation: 'Implement query complexity scoring, maximum depth limits, and per-query cost budgets.' },
  { id: 'DO-026', title: 'Denial of service via database connection pool exhaustion from long-running queries', severity: 'Medium', cwe: 'CWE-400', description: 'A poorly optimized or attacker-triggered query holds a database connection for an extended period, and repeated triggering exhausts the shared connection pool for all requests.', example: 'A missing index causes a filter operation to take 30+ seconds, and repeated requests exhaust the entire connection pool.', mitigation: 'Set query timeouts, optimize slow queries, and isolate connection pools per critical workload.' },
  { id: 'DO-027', title: 'Denial of service via CDN cache-key collision poisoning legitimate content unavailable', severity: 'Low', cwe: 'CWE-400', description: 'A crafted request causes the CDN to cache an error or empty response under the key normally used for valid content, making the legitimate content unavailable to all subsequent users until cache expiry.', example: 'A request with a malformed header triggers a 502 response cached under the normal content URL, denying access to all visitors until TTL expiry.', mitigation: 'Configure CDN to avoid caching error responses and validate origin response status before caching.' },
  { id: 'DO-028', title: 'Denial of service through exhaustive brute-force triggering WAF false-positive lockout', severity: 'Low', cwe: 'CWE-400', description: 'An attacker deliberately triggers WAF or IPS false positives against a legitimate partner\'s IP range, causing the automated blocking system to deny that partner\'s legitimate traffic.', example: 'Spoofed malicious-looking traffic from a partner\'s IP range triggers automatic IP blocking, cutting off the partner\'s legitimate integration.', mitigation: 'Require manual review before automatically blocking known partner IP ranges; use reputation scoring rather than binary triggers.' },
  { id: 'DO-029', title: 'Denial of service via IoT botnet leveraging compromised devices', severity: 'High', cwe: 'CWE-400', description: 'A large number of compromised IoT devices (cameras, routers) are coordinated into a botnet used to launch massive volumetric attacks against a target.', example: 'A botnet of hundreds of thousands of compromised routers launches a multi-hundred-gigabit attack against a target service.', mitigation: 'Deploy upstream DDoS scrubbing capable of absorbing large-scale botnet traffic and maintain incident response playbooks for sustained attacks.' },
  { id: 'DO-030', title: 'Denial of service via race condition triggering deadlock in concurrent request handling', severity: 'Medium', cwe: 'CWE-833', description: 'Specific concurrent request patterns trigger a deadlock in shared resource locking logic, hanging worker threads indefinitely and gradually exhausting available workers.', example: 'A specific sequence of concurrent update requests to the same record deadlocks the database connection handling thread.', mitigation: 'Use consistent lock ordering, deadlock detection with automatic rollback, and query timeouts.' },
  { id: 'DO-031', title: 'Denial of service via forced password/key rotation triggering mass re-authentication storm', severity: 'Low', cwe: 'CWE-400', description: 'A mass credential rotation event (e.g., after a breach) causes every client to re-authenticate simultaneously, overwhelming the authentication service with a legitimate but concentrated load spike.', example: 'A forced password reset for all 2 million users triggers a synchronized login storm that overwhelms the auth service.', mitigation: 'Stagger forced rotation notifications and scale authentication infrastructure ahead of planned mass events.' },
  { id: 'DO-032', title: 'Denial of service via malicious webhook retry storm', severity: 'Medium', cwe: 'CWE-400', description: 'A webhook consumer intentionally or accidentally always returns failure, causing the sender\'s retry logic to generate an ever-increasing volume of retry traffic that overwhelms the sender\'s own outbound infrastructure.', example: 'A misconfigured partner endpoint always returns 500, causing exponential retry storms that saturate the outbound webhook dispatcher.', mitigation: 'Implement retry backoff caps, circuit breakers, and automatic webhook endpoint disabling after sustained failure.' },
  { id: 'DO-033', title: 'Denial of service through resource-intensive PDF/report rendering abuse', severity: 'Medium', cwe: 'CWE-400', description: 'A feature that renders complex documents (PDF generation, chart rendering) on demand is triggered repeatedly by an attacker, exhausting rendering-worker CPU and memory.', example: 'Repeated requests for a complex multi-page PDF report exhaust the rendering worker pool, delaying reports for all users.', mitigation: 'Queue and rate-limit expensive rendering operations with per-user concurrency caps.' },
  { id: 'DO-034', title: 'Denial of service via IP-based CAPTCHA bypass overwhelming manual review queue', severity: 'Low', cwe: 'CWE-400', description: 'An attacker triggers CAPTCHA challenges at massive scale using a distributed botnet, then routes solved challenges through cheap human-solving farms, effectively overwhelming downstream systems anyway while appearing legitimate.', example: 'A CAPTCHA-solving farm processes tens of thousands of challenges per hour, allowing an underlying credential-stuffing attack to continue at scale.', mitigation: 'Combine CAPTCHA with behavioral analysis and device fingerprinting rather than relying on CAPTCHA alone.' },
  { id: 'DO-035', title: 'Denial of service via load balancer health-check amplification', severity: 'Low', cwe: 'CWE-400', description: 'An attacker triggers repeated backend failures specifically to cause the load balancer\'s health-check system to remove healthy nodes from rotation, concentrating traffic on remaining nodes and cascading the outage.', example: 'Targeted failure injection on one node causes the load balancer to remove it, overloading remaining nodes into a cascading failure.', mitigation: 'Use gradual, threshold-based health-check removal with automatic re-addition and capacity headroom.' },
  { id: 'DO-036', title: 'Denial of service via malicious Content-Length mismatch causing request queue stall', severity: 'Low', cwe: 'CWE-400', description: 'A crafted request declares a Content-Length larger than the actual body sent, causing the server to wait indefinitely for the remaining bytes, tying up a worker connection.', example: 'Many connections each declaring an oversized Content-Length but never completing the body exhaust available worker threads.', mitigation: 'Enforce strict body-read timeouts independent of the declared Content-Length header.' },
  { id: 'DO-037', title: 'Denial of service via poison pill message crashing all queue consumers', severity: 'Medium', cwe: 'CWE-400', description: 'A malformed message placed into a shared message queue repeatedly crashes every consumer that attempts to process it, and without a dead-letter mechanism, the message is endlessly redelivered.', example: 'A malformed order message crashes the order-processing service on every redelivery attempt, halting all order processing.', mitigation: 'Implement dead-letter queues and maximum-redelivery limits so poison messages are isolated rather than looping indefinitely.' },
  { id: 'DO-038', title: 'Denial of service via exhausting rate-limit exemption list through IP rotation', severity: 'Low', cwe: 'CWE-400', description: 'An attacker discovers and abuses a rate-limit exemption intended for internal/partner IPs by rotating through spoofed or compromised IPs within the exempted range.', example: 'An attacker routes traffic through a compromised host within a partner\'s exempted IP range, bypassing rate limiting entirely.', mitigation: 'Pair IP-based exemptions with additional authentication (mTLS/API keys) rather than IP address alone.' },
  { id: 'DO-039', title: 'Denial of service via forced re-indexing of search infrastructure', severity: 'Medium', cwe: 'CWE-400', description: 'An attacker triggers repeated bulk content updates specifically designed to force expensive full or partial search-index rebuilds, degrading search availability for all users.', example: 'Automated rapid-fire content edits repeatedly trigger full-text index rebuilds, degrading search performance for the whole platform.', mitigation: 'Batch and debounce index updates, and rate-limit content modification operations that trigger re-indexing.' },
  { id: 'DO-040', title: 'Denial of service via crafted regular payload exploiting garbage collection pauses', severity: 'Low', cwe: 'CWE-400', description: 'An attacker crafts requests that generate a large volume of short-lived objects, triggering excessive garbage-collection pauses that stall request processing for all users on the affected process.', example: 'Repeated large object-allocation requests trigger multi-second GC pauses, causing timeouts across unrelated concurrent requests.', mitigation: 'Tune garbage collector settings, isolate memory-intensive workloads, and cap allocation size per request.' },
  { id: 'DO-041', title: 'Denial of service via satellite/edge device jamming or physical signal interference', severity: 'Medium', cwe: 'CWE-1247', description: 'An attacker physically jams or interferes with the wireless signal (Wi-Fi, cellular, satellite) required for a device or facility to communicate, denying service at the physical layer.', example: 'A jamming device near a retail location disrupts point-of-sale connectivity, halting all transactions.', mitigation: 'Use frequency-hopping or redundant communication paths (wired failover) for critical connectivity.' },
  { id: 'DO-042', title: 'Denial of service via exhausting rate-limited third-party CAPTCHA verification API quota', severity: 'Low', cwe: 'CWE-400', description: 'An attacker generates enough legitimate-looking CAPTCHA verification requests to exhaust the organization\'s quota with the third-party CAPTCHA verification service, causing all subsequent legitimate verifications to fail open or fail closed.', example: 'A flood of CAPTCHA-triggering signup attempts exhausts the daily verification API quota, blocking all new legitimate signups for the rest of the day.', mitigation: 'Monitor third-party API quota consumption with alerting and negotiate burst capacity for critical verification services.' },
];

/* ============================================================================
   SECTION 11: THREAT LIBRARY -- ELEVATION OF PRIVILEGE (42 threats)
   ========================================================================== */

const THREAT_LIBRARY_EOP = [
  { id: 'EP-001', title: 'Insecure direct object reference enabling horizontal privilege escalation', severity: 'High', cwe: 'CWE-639', description: 'A user modifies a resource identifier in a request to access or modify another user\'s data without proper ownership verification.', example: 'Changing an order ID in a URL lets a user cancel another customer\'s order.', mitigation: 'Verify resource ownership server-side on every request that accepts a client-supplied identifier.' },
  { id: 'EP-002', title: 'Mass assignment allowing privileged field modification', severity: 'High', cwe: 'CWE-915', description: 'An API binds an entire request body directly to an internal model, allowing an attacker to set fields such as "isAdmin" or "role" that should not be user-writable.', example: 'A profile update request includes an unexpected "role":"admin" field that the server blindly applies.', mitigation: 'Use explicit allow-lists of writable fields rather than binding entire request bodies to internal models.' },
  { id: 'EP-003', title: 'Hidden UI element as the only access control for a privileged feature', severity: 'High', cwe: 'CWE-284', description: 'An administrative feature is hidden from the UI for non-admin users but the underlying API endpoint performs no server-side authorization check.', example: 'A hidden "delete all users" button is inaccessible in the UI but the API endpoint executes for any authenticated user who calls it directly.', mitigation: 'Enforce authorization server-side for every privileged action, independent of UI visibility.' },
  { id: 'EP-004', title: 'Container escape via shared kernel vulnerability', severity: 'Critical', cwe: 'CWE-1247', description: 'A vulnerability in the container runtime or shared kernel allows code running inside a container to break out and gain host-level privileges.', example: 'A crafted container workload exploits a runc vulnerability to gain root access on the underlying host.', mitigation: 'Apply prompt patching, use rootless containers, and enforce seccomp/AppArmor profiles restricting syscalls.' },
  { id: 'EP-005', title: 'Local privilege escalation via unpatched OS kernel vulnerability', severity: 'Critical', cwe: 'CWE-269', description: 'A known kernel vulnerability allows a low-privileged local user or process to escalate to root/SYSTEM privileges.', example: 'A standard user exploits an unpatched Dirty Pipe-class kernel bug to gain root shell access.', mitigation: 'Maintain aggressive patch SLAs specifically for privilege-escalation-class CVEs across all hosts.' },
  { id: 'EP-006', title: 'Overly broad IAM policy granting excessive cloud permissions', severity: 'High', cwe: 'CWE-269', description: 'A cloud IAM role or policy grants wildcard or overly broad permissions far beyond what the associated workload actually requires.', example: 'A Lambda function with "s3:*" permissions is compromised and used to read every bucket in the account.', mitigation: 'Apply least-privilege IAM policies scoped to specific resources and actions, reviewed regularly.' },
  { id: 'EP-007', title: 'Default or forgotten administrative account with weak credentials', severity: 'High', cwe: 'CWE-798', description: 'A default administrative account remains active with an unchanged or weak default password, providing direct elevation of privilege to anyone who discovers it.', example: 'A forgotten "admin/admin123" account created during initial setup is discovered and used to gain full system access.', mitigation: 'Inventory all administrative accounts, disable unused defaults, and enforce strong unique credentials plus MFA.' },
  { id: 'EP-008', title: 'Insecure deserialization enabling remote code execution', severity: 'Critical', cwe: 'CWE-502', description: 'Untrusted data is deserialized without validation, allowing an attacker to construct a malicious object graph that executes arbitrary code with the application\'s privileges.', example: 'A crafted serialized Java object triggers a known gadget chain, executing OS commands with the web application\'s privileges.', mitigation: 'Avoid native deserialization of untrusted data; use schema-validated formats and allow-list permitted classes if native deserialization is unavoidable.' },
  { id: 'EP-009', title: 'Overly permissive sudoers configuration', severity: 'High', cwe: 'CWE-269', description: 'A sudoers rule grants a low-privileged user the ability to run commands as root without a password, or grants access to commands that can be abused to spawn a root shell.', example: 'A NOPASSWD sudo rule for a text editor allows a user to use the editor\'s shell-escape feature to gain a root shell.', mitigation: 'Restrict sudoers rules to specific, narrowly scoped commands and avoid granting shell-capable binaries.' },
  { id: 'EP-010', title: 'Missing separation of duties in privileged change approval', severity: 'Medium', cwe: 'CWE-284', description: 'A single individual can both request and approve a high-impact privileged change, removing the check that separation of duties is meant to provide.', example: 'A developer both submits and self-approves a production database permission change.', mitigation: 'Require a separate, independent approver for all high-impact privileged changes.' },
  { id: 'EP-011', title: 'Standing administrative access instead of just-in-time privilege', severity: 'Medium', cwe: 'CWE-269', description: 'Administrative privileges are permanently granted rather than provisioned only for the duration needed, increasing the window of exposure if the account is compromised.', example: 'A compromised account with permanent admin rights is used for lateral movement weeks after the account owner last actually needed elevated access.', mitigation: 'Adopt just-in-time privileged access management (PAM) that grants time-bound, audited elevation.' },
  { id: 'EP-012', title: 'Multi-tenant privilege escalation via missing tenant isolation in query layer', severity: 'Critical', cwe: 'CWE-668', description: 'A shared multi-tenant application fails to enforce tenant scoping consistently at the data layer, allowing one tenant\'s administrator to gain access to another tenant\'s administrative functions.', example: 'A tenant admin API call omits a tenant-ID filter on a background job, inadvertently granting cross-tenant admin actions.', mitigation: 'Enforce tenant-scoping at the data-access layer for every query, verified through automated cross-tenant isolation tests.' },
  { id: 'EP-013', title: 'Privilege escalation via unsandboxed third-party plugin execution', severity: 'High', cwe: 'CWE-269', description: 'A plugin or extension system executes third-party code with the full privileges of the host application rather than a restricted capability set.', example: 'A malicious CMS plugin uses its full application-level file-system access to install a persistent backdoor.', mitigation: 'Sandbox third-party plugins with capability-based permission scopes limiting file, network, and API access.' },
  { id: 'EP-014', title: 'Privilege escalation via SQL injection reaching database admin functions', severity: 'Critical', cwe: 'CWE-89', description: 'An SQL injection vulnerability is leveraged not just to read data but to invoke database administrative functions (e.g., xp_cmdshell) that execute operating-system commands.', example: 'A SQL injection payload invokes xp_cmdshell to execute arbitrary commands on the database host with SQL Server service privileges.', mitigation: 'Fix the underlying injection vulnerability and disable dangerous database administrative functions unless explicitly required.' },
  { id: 'EP-015', title: 'Privilege escalation via path traversal to overwrite a privileged startup script', severity: 'High', cwe: 'CWE-22', description: 'A file-write vulnerability with insufficient path validation allows an attacker to overwrite a script or configuration file that runs with elevated privileges at startup.', example: 'A path-traversal file write overwrites a cron job script executed as root, achieving persistent privilege escalation.', mitigation: 'Validate and canonicalize all file paths against a strict allow-list before performing any write operation.' },
  { id: 'EP-016', title: 'Privilege escalation via JWT role claim tampering due to weak signature validation', severity: 'Critical', cwe: 'CWE-347', description: 'A JWT\'s role or permission claim is trusted without properly verifying the token signature, allowing an attacker to forge a token claiming elevated privileges.', example: 'A modified JWT with "role":"admin" is accepted because the server fails to verify the signature under certain conditions.', mitigation: 'Strictly verify JWT signatures using a fixed, expected algorithm and key on every request.' },
  { id: 'EP-017', title: 'Privilege escalation via exposed Kubernetes RBAC misconfiguration', severity: 'High', cwe: 'CWE-269', description: 'A Kubernetes RBAC role binding grants a service account cluster-wide permissions (e.g., cluster-admin) far beyond what its workload requires.', example: 'A compromised pod with a cluster-admin-bound service account is used to create new privileged pods across the entire cluster.', mitigation: 'Apply least-privilege RBAC roles scoped to specific namespaces and resources for every service account.' },
  { id: 'EP-018', title: 'Privilege escalation through unvalidated OAuth scope elevation during token refresh', severity: 'Medium', cwe: 'CWE-269', description: 'A token refresh flow fails to re-validate the originally granted scopes, allowing a client to silently request and receive an elevated scope set on refresh.', example: 'A refreshed token includes an additional administrative scope never explicitly granted by the user during original consent.', mitigation: 'Re-validate and constrain granted scopes to the original consent on every token refresh.' },
  { id: 'EP-019', title: 'Privilege escalation via improperly scoped API gateway pass-through headers', severity: 'Medium', cwe: 'CWE-290', description: 'An API gateway forwards an internal trust header (e.g., X-Internal-Admin: true) that a downstream service trusts implicitly, allowing an external caller to set that header directly if the gateway does not strip it.', example: 'A crafted external request includes the internal trust header directly, and a misconfigured gateway forwards it unmodified.', mitigation: 'Strip and overwrite all internal trust headers at the gateway boundary regardless of inbound value.' },
  { id: 'EP-020', title: 'Privilege escalation via race condition in role-assignment workflow', severity: 'Medium', cwe: 'CWE-362', description: 'A time-of-check-to-time-of-use gap in a role assignment or permission-grant workflow allows a user to perform a privileged action during a brief window before a downgrade takes effect.', example: 'A user performs an admin action in the small window between an admin-demotion request being submitted and actually applied.', mitigation: 'Use atomic, transactional permission updates that eliminate the check-then-use gap.' },
  { id: 'EP-021', title: 'Privilege escalation via abusing "break glass" emergency access procedure', severity: 'Medium', cwe: 'CWE-269', description: 'An emergency access procedure intended for rare incident response is invoked routinely or without adequate review, effectively becoming a standing elevated-privilege backdoor.', example: 'An engineer repeatedly invokes "break glass" access for routine tasks because it is faster than the normal approval process, and reviews never actually happen.', mitigation: 'Automatically time-limit break-glass access and mandate a documented post-use review for every invocation.' },
  { id: 'EP-022', title: 'Privilege escalation via unsafe eval/exec of user-supplied expressions', severity: 'Critical', cwe: 'CWE-95', description: 'A feature that evaluates user-supplied formulas, templates, or expressions uses an unsandboxed eval-like function, allowing arbitrary code execution with the application\'s privileges.', example: 'A "custom formula" feature in a reporting tool allows a crafted expression to execute arbitrary server-side code.', mitigation: 'Never use eval on untrusted input; use a sandboxed expression parser with a restricted, safe function set.' },
  { id: 'EP-023', title: 'Privilege escalation via SSRF reaching cloud metadata service', severity: 'Critical', cwe: 'CWE-918', description: 'A server-side request forgery vulnerability is used to reach the internal cloud instance metadata endpoint, retrieving temporary credentials associated with the instance\'s IAM role.', example: 'An SSRF payload targets the internal 169.254.169.254 metadata endpoint, extracting instance IAM role credentials.', mitigation: 'Enforce IMDSv2 (token-required metadata access), block internal metadata IP ranges at the application/network layer, and validate outbound request destinations.' },
  { id: 'EP-024', title: 'Privilege escalation via abuse of self-service password-reset for administrator accounts', severity: 'High', cwe: 'CWE-640', description: 'A self-service password-reset flow that is safe for standard users is also usable to reset administrator account passwords, without additional verification appropriate to the account\'s elevated privilege.', example: 'An attacker uses the standard password-reset flow to take over a poorly protected shared administrator email account.', mitigation: 'Require additional out-of-band verification for password resets on privileged accounts.' },
  { id: 'EP-025', title: 'Privilege escalation via GraphQL field-level authorization gap', severity: 'High', cwe: 'CWE-863', description: 'A GraphQL schema enforces authorization at the query/operation level but individual fields resolving privileged data lack independent authorization checks.', example: 'A regular query field unintentionally exposes an "internalNotes" field only meant for administrators, due to missing field-level checks.', mitigation: 'Apply authorization checks at the resolver/field level, not only at the top-level query or mutation.' },
  { id: 'EP-026', title: 'Privilege escalation via reused service account across environments', severity: 'Medium', cwe: 'CWE-269', description: 'The same service account credential is used across development, staging, and production environments, so compromising a lower-security environment grants access to production.', example: 'A leaked staging environment credential turns out to be the same service account used in production, granting immediate elevated access.', mitigation: 'Use distinct, environment-scoped service account credentials with no cross-environment reuse.' },
  { id: 'EP-027', title: 'Privilege escalation via CI/CD pipeline secrets exposure to unprivileged jobs', severity: 'High', cwe: 'CWE-269', description: 'A CI/CD pipeline exposes highly privileged deployment secrets to build jobs that do not need them, such as jobs triggered by external contributor pull requests.', example: 'A pull-request-triggered test job has access to the same production deployment secret used by the release job, and a malicious PR exfiltrates it.', mitigation: 'Scope secrets narrowly to only the specific pipeline stages that require them, and never expose deployment secrets to untrusted trigger sources.' },
  { id: 'EP-028', title: 'Privilege escalation via abusing a vertical trust relationship between microservices', severity: 'High', cwe: 'CWE-269', description: 'A low-privilege internal microservice is implicitly trusted by a high-privilege service due to network-level trust alone, letting a compromise of the low-privilege service cascade into full access to the high-privilege one.', example: 'A compromised internal logging service is trusted implicitly by the billing service due to shared network trust, enabling privilege escalation into billing operations.', mitigation: 'Enforce explicit, scoped service-to-service authorization (mTLS + policy) rather than implicit network trust.' },
  { id: 'EP-029', title: 'Privilege escalation via abuse of impersonation/support-login feature scope', severity: 'High', cwe: 'CWE-269', description: 'A "login as user" support feature does not restrict which actions can be performed while impersonating, allowing a support agent to perform actions (like changing security settings) beyond legitimate support needs.', example: 'A support agent uses the impersonation feature to change a customer\'s registered email address and take over the account.', mitigation: 'Restrict impersonation sessions to a limited, explicitly allow-listed set of read-only or support-relevant actions.' },
  { id: 'EP-030', title: 'Privilege escalation via unsafe file permission defaults on installed application', severity: 'Medium', cwe: 'CWE-276', description: 'An installer sets overly permissive file or directory permissions (world-writable) on privileged application files, allowing a low-privileged local user to modify them and gain elevated execution.', example: 'A world-writable service executable is replaced by a local low-privileged user, executing with the service\'s elevated privileges on next restart.', mitigation: 'Apply least-privilege file permissions during installation, restricting write access to the owning privileged account only.' },
  { id: 'EP-031', title: 'Privilege escalation via abuse of API versioning inconsistency in authorization enforcement', severity: 'Medium', cwe: 'CWE-863', description: 'A newer API version enforces stricter authorization checks than an older, still-active API version, allowing an attacker to bypass the stricter checks by calling the legacy version.', example: 'A v1 endpoint still exists without the field-level authorization added in v2, letting an attacker retrieve privileged data via the old version.', mitigation: 'Apply consistent authorization checks across all active API versions, or fully decommission outdated versions.' },
  { id: 'EP-032', title: 'Privilege escalation via unauthenticated internal debug/admin endpoint left enabled', severity: 'Critical', cwe: 'CWE-489', description: 'A debug or administrative endpoint intended only for development is accidentally left enabled and reachable in production without authentication.', example: 'A "/debug/set-role" endpoint intended for local development testing is discovered still active in production.', mitigation: 'Strip debug/admin endpoints from production builds via build-time flags, verified by automated deployment checks.' },
  { id: 'EP-033', title: 'Privilege escalation via cross-tenant admin API key reuse in SaaS integration', severity: 'High', cwe: 'CWE-269', description: 'An integration platform stores admin-level API keys for multiple tenant accounts in a shared credential store without adequate isolation, allowing a compromise of the platform to grant access across all connected tenants.', example: 'A compromised integration platform exposes admin API keys for every connected customer account simultaneously.', mitigation: 'Use per-tenant scoped, minimally privileged OAuth tokens rather than shared admin-level API keys for third-party integrations.' },
  { id: 'EP-034', title: 'Privilege escalation via abuse of trusted CI runner with access to production network', severity: 'High', cwe: 'CWE-269', description: 'A CI/CD runner used for building untrusted external contributions also has network access to production systems, allowing a malicious build script to pivot directly into production.', example: 'A malicious build script in an external contributor\'s pull request uses the CI runner\'s production network access to reach an internal admin API.', mitigation: 'Isolate CI runners used for untrusted code from any network path to production systems.' },
  { id: 'EP-035', title: 'Privilege escalation via reused local admin password across many endpoints', severity: 'High', cwe: 'CWE-798', description: 'The same local administrator password is used across every workstation or server in a fleet, so compromising one host\'s credential grants administrative access to the entire fleet.', example: 'A leaked local admin password from one compromised laptop grants an attacker administrative access across the entire corporate laptop fleet.', mitigation: 'Use unique, randomized local administrator passwords per host, managed via a privileged access management (LAPS-style) solution.' },
  { id: 'EP-036', title: 'Privilege escalation via insufficiently scoped personal access tokens', severity: 'Medium', cwe: 'CWE-269', description: 'A personal access token system allows tokens to be created with broad, unscoped permissions equivalent to the full user account rather than task-specific scopes.', example: 'A leaked personal access token intended only for read-only CI automation actually grants full account administrative rights.', mitigation: 'Support fine-grained, purpose-scoped personal access tokens with the minimum necessary permission set.' },
  { id: 'EP-037', title: 'Privilege escalation via missing re-authentication before sensitive privilege change', severity: 'Medium', cwe: 'CWE-620', description: 'A user\'s active session, once authenticated, can grant themselves or others elevated privileges without any re-authentication step, so a hijacked session immediately grants full elevation capability.', example: 'A hijacked session token is used to add a new administrator account without any additional confirmation step.', mitigation: 'Require step-up re-authentication (password or MFA) immediately before any privilege-granting action.' },
  { id: 'EP-038', title: 'Privilege escalation via abusing an overly trusting webhook-triggered automation', severity: 'Medium', cwe: 'CWE-269', description: 'An automation system executes privileged actions in response to webhook events without verifying the event\'s authenticity, allowing a forged webhook to trigger privileged automated actions.', example: 'A forged "user upgraded to enterprise" webhook triggers an automation that grants elevated internal permissions without verification.', mitigation: 'Verify webhook signatures before triggering any privileged automated action.' },
  { id: 'EP-039', title: 'Privilege escalation via insufficiently isolated serverless function execution role', severity: 'Medium', cwe: 'CWE-269', description: 'Multiple serverless functions with differing sensitivity levels share the same broad execution role, so compromising a low-sensitivity function grants the privileges needed to affect high-sensitivity operations.', example: 'A compromised low-risk image-resizing function shares an execution role with the payment-processing function, enabling privilege escalation.', mitigation: 'Assign distinct, minimally scoped execution roles per function based on its actual sensitivity and required permissions.' },
  { id: 'EP-040', title: 'Privilege escalation via abusing a misconfigured OIDC trust relationship', severity: 'High', cwe: 'CWE-295', description: 'An OpenID Connect trust configuration accepts tokens from an overly broad set of issuers or fails to validate the audience claim, allowing an attacker with a token from a different, less-trusted context to gain elevated access.', example: 'A cloud role trusts any GitHub Actions workflow rather than a specific repository and branch, letting an unrelated repository assume the privileged role.', mitigation: 'Scope OIDC trust relationships tightly to specific issuers, subjects, audiences, and (for CI use cases) specific repositories and branches.' },
  { id: 'EP-041', title: 'Privilege escalation via default-allow firewall rule left from initial provisioning', severity: 'Medium', cwe: 'CWE-284', description: 'A temporary broad-access firewall rule created during initial system provisioning is never removed, providing an ongoing path for lateral movement and privilege escalation.', example: 'A "allow all from 0.0.0.0/0 for setup" security group rule created during initial deployment is still active a year later.', mitigation: 'Track and automatically expire temporary provisioning rules, verified through periodic firewall rule audits.' },
  { id: 'EP-042', title: 'Privilege escalation via abuse of shared build cache poisoning subsequent privileged builds', severity: 'Medium', cwe: 'CWE-829', description: 'A shared build cache used across multiple pipelines, including privileged deployment pipelines, is poisoned by an untrusted build, causing a subsequent privileged build to incorporate malicious cached artifacts.', example: 'A malicious dependency cached during an untrusted pull-request build is later reused unmodified by the trusted production deployment pipeline.', mitigation: 'Isolate build caches between untrusted and privileged pipelines, or validate cache artifact integrity before reuse in privileged builds.' },
];

// Combined threat library keyed by STRIDE category
const THREAT_LIBRARY = {
  spoofing: THREAT_LIBRARY_SPOOFING,
  tampering: THREAT_LIBRARY_TAMPERING,
  repudiation: THREAT_LIBRARY_REPUDIATION,
  information_disclosure: THREAT_LIBRARY_INFO_DISCLOSURE,
  denial_of_service: THREAT_LIBRARY_DOS,
  elevation_of_privilege: THREAT_LIBRARY_EOP,
};

/* ============================================================================
   SECTION 12: COMPLIANCE MAPPING DATA -- NIST 800-53, ISO 27001, CIS Controls
   ========================================================================== */

const NIST_800_53_CONTROLS = [
  { id: 'AC-2', family: 'Access Control', title: 'Account Management', description: 'Manages information system accounts, including establishment, activation, modification, review, and removal.' },
  { id: 'AC-3', family: 'Access Control', title: 'Access Enforcement', description: 'Enforces approved authorizations for logical access in accordance with applicable policy.' },
  { id: 'AC-4', family: 'Access Control', title: 'Information Flow Enforcement', description: 'Controls information flow between interconnected systems based on organizational policies.' },
  { id: 'AC-6', family: 'Access Control', title: 'Least Privilege', description: 'Employs the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.' },
  { id: 'AC-7', family: 'Access Control', title: 'Unsuccessful Logon Attempts', description: 'Enforces a limit of consecutive invalid logon attempts and automatically locks the account or delays next attempt.' },
  { id: 'AC-11', family: 'Access Control', title: 'Device Lock', description: 'Prevents further access by initiating a device lock after a period of inactivity.' },
  { id: 'AC-17', family: 'Access Control', title: 'Remote Access', description: 'Establishes and manages usage restrictions and implementation guidance for remote access.' },
  { id: 'AC-25', family: 'Access Control', title: 'Reference Monitor', description: 'Implements a reference monitor for access control that is tamperproof and always invoked.' },
  { id: 'AT-2', family: 'Awareness and Training', title: 'Literacy Training and Awareness', description: 'Provides security and privacy literacy training to system users.' },
  { id: 'AU-2', family: 'Audit and Accountability', title: 'Event Logging', description: 'Identifies the types of events that the system is capable of logging in support of the audit function.' },
  { id: 'AU-3', family: 'Audit and Accountability', title: 'Content of Audit Records', description: 'Ensures audit records contain information establishing what, when, where, source, and outcome of events.' },
  { id: 'AU-6', family: 'Audit and Accountability', title: 'Audit Record Review, Analysis, and Reporting', description: 'Reviews and analyzes system audit records for indications of inappropriate or unusual activity.' },
  { id: 'AU-9', family: 'Audit and Accountability', title: 'Protection of Audit Information', description: 'Protects audit information and audit tools from unauthorized access, modification, and deletion.' },
  { id: 'AU-10', family: 'Audit and Accountability', title: 'Non-repudiation', description: 'Protects against an individual falsely denying having performed a particular action.' },
  { id: 'AU-11', family: 'Audit and Accountability', title: 'Audit Record Retention', description: 'Retains audit records for a defined time period to provide support for after-the-fact investigations.' },
  { id: 'AU-12', family: 'Audit and Accountability', title: 'Audit Record Generation', description: 'Provides audit record generation capability for the events defined in AU-2 at organization-defined components.' },
  { id: 'CA-7', family: 'Assessment, Authorization, and Monitoring', title: 'Continuous Monitoring', description: 'Develops and implements a continuous monitoring strategy including ongoing assessments of security controls.' },
  { id: 'CM-2', family: 'Configuration Management', title: 'Baseline Configuration', description: 'Develops, documents, and maintains a current baseline configuration of the system.' },
  { id: 'CM-6', family: 'Configuration Management', title: 'Configuration Settings', description: 'Establishes and documents mandatory configuration settings using security configuration checklists.' },
  { id: 'CM-7', family: 'Configuration Management', title: 'Least Functionality', description: 'Configures the system to provide only essential capabilities, restricting unnecessary functions, ports, and services.' },
  { id: 'CM-8', family: 'Configuration Management', title: 'System Component Inventory', description: 'Develops and maintains an inventory of system components that accurately reflects the current system.' },
  { id: 'CP-9', family: 'Contingency Planning', title: 'System Backup', description: 'Conducts backups of user-level and system-level information, protecting confidentiality, integrity, and availability.' },
  { id: 'CP-10', family: 'Contingency Planning', title: 'System Recovery and Reconstitution', description: 'Provides for the recovery and reconstitution of the system to a known state after a disruption or failure.' },
  { id: 'IA-2', family: 'Identification and Authentication', title: 'Identification and Authentication (Organizational Users)', description: 'Uniquely identifies and authenticates organizational users, or processes acting on their behalf.' },
  { id: 'IA-4', family: 'Identification and Authentication', title: 'Identifier Management', description: 'Manages system identifiers by receiving authorization, selecting, assigning, and preventing reuse.' },
  { id: 'IA-5', family: 'Identification and Authentication', title: 'Authenticator Management', description: 'Manages system authenticators by verifying identity, establishing initial content, and enforcing lifecycle rules.' },
  { id: 'IA-8', family: 'Identification and Authentication', title: 'Identification and Authentication (Non-Organizational Users)', description: 'Uniquely identifies and authenticates non-organizational users or processes acting on their behalf.' },
  { id: 'IA-11', family: 'Identification and Authentication', title: 'Re-authentication', description: 'Requires users and devices to re-authenticate when organization-defined circumstances or situations require it.' },
  { id: 'IR-4', family: 'Incident Response', title: 'Incident Handling', description: 'Implements an incident handling capability for security incidents including preparation, detection, and analysis.' },
  { id: 'IR-5', family: 'Incident Response', title: 'Incident Monitoring', description: 'Tracks and documents system security incidents.' },
  { id: 'IR-6', family: 'Incident Response', title: 'Incident Reporting', description: 'Requires personnel to report suspected security incidents within a defined time period.' },
  { id: 'PE-3', family: 'Physical and Environmental Protection', title: 'Physical Access Control', description: 'Enforces physical access authorizations at defined entry and exit points.' },
  { id: 'PL-8', family: 'Planning', title: 'Security and Privacy Architectures', description: 'Develops security and privacy architectures for the system aligned with enterprise architecture.' },
  { id: 'RA-3', family: 'Risk Assessment', title: 'Risk Assessment', description: 'Conducts risk assessments including the likelihood and magnitude of harm from unauthorized system access.' },
  { id: 'RA-5', family: 'Risk Assessment', title: 'Vulnerability Monitoring and Scanning', description: 'Monitors and scans for vulnerabilities in the system and hosted applications on a defined frequency.' },
  { id: 'SA-11', family: 'System and Services Acquisition', title: 'Developer Testing and Evaluation', description: 'Requires developers to perform unit, integration, system, and security testing/evaluation.' },
  { id: 'SA-15', family: 'System and Services Acquisition', title: 'Development Process, Standards, and Tools', description: 'Requires developers to follow a documented development process that addresses security requirements.' },
  { id: 'SC-5', family: 'System and Communications Protection', title: 'Denial-of-Service Protection', description: 'Protects against or limits the effects of denial-of-service events.' },
  { id: 'SC-7', family: 'System and Communications Protection', title: 'Boundary Protection', description: 'Monitors and controls communications at external and key internal boundaries of the system.' },
  { id: 'SC-8', family: 'System and Communications Protection', title: 'Transmission Confidentiality and Integrity', description: 'Protects the confidentiality and integrity of transmitted information.' },
  { id: 'SC-12', family: 'System and Communications Protection', title: 'Cryptographic Key Establishment and Management', description: 'Establishes and manages cryptographic keys when cryptography is employed.' },
  { id: 'SC-13', family: 'System and Communications Protection', title: 'Cryptographic Protection', description: 'Determines and implements required cryptographic uses and types in accordance with applicable law and policy.' },
  { id: 'SC-23', family: 'System and Communications Protection', title: 'Session Authenticity', description: 'Protects the authenticity of communications sessions, including protection against session hijacking.' },
  { id: 'SC-28', family: 'System and Communications Protection', title: 'Protection of Information at Rest', description: 'Protects the confidentiality and integrity of information at rest.' },
  { id: 'SI-2', family: 'System and Information Integrity', title: 'Flaw Remediation', description: 'Identifies, reports, and corrects system flaws, and tests software/firmware updates before installation.' },
  { id: 'SI-3', family: 'System and Information Integrity', title: 'Malicious Code Protection', description: 'Implements malicious code protection mechanisms at system entry and exit points.' },
  { id: 'SI-4', family: 'System and Information Integrity', title: 'System Monitoring', description: 'Monitors the system to detect attacks, indicators of compromise, and unauthorized use.' },
  { id: 'SI-7', family: 'System and Information Integrity', title: 'Software, Firmware, and Information Integrity', description: 'Employs integrity verification tools to detect unauthorized changes to software, firmware, and information.' },
  { id: 'SI-10', family: 'System and Information Integrity', title: 'Information Input Validation', description: 'Checks the validity of information inputs against defined criteria for format, syntax, and content.' },
  { id: 'SR-3', family: 'Supply Chain Risk Management', title: 'Supply Chain Controls and Processes', description: 'Establishes processes to identify and address weaknesses or deficiencies in the supply chain elements.' },
];

const ISO_27001_CONTROLS = [
  { id: 'A.5.15', title: 'Access control', description: 'Rules to control physical and logical access to information and other associated assets shall be established based on business and information security requirements.' },
  { id: 'A.5.16', title: 'Identity management', description: 'The full life cycle of identities shall be managed to enable the unique identification of individuals and systems accessing the organization\'s information.' },
  { id: 'A.5.17', title: 'Authentication information', description: 'Allocation and management of authentication information shall be controlled by a management process, including advice on proper handling.' },
  { id: 'A.5.18', title: 'Access rights', description: 'Access rights to information and other associated assets shall be provisioned, reviewed, modified, and removed in accordance with policy.' },
  { id: 'A.5.19', title: 'Information security in supplier relationships', description: 'Processes and procedures shall be defined to manage the information security risks associated with the use of supplier products or services.' },
  { id: 'A.5.23', title: 'Information security for use of cloud services', description: 'Processes for acquisition, use, management, and exit from cloud services shall be established in accordance with security requirements.' },
  { id: 'A.5.24', title: 'Information security incident management planning and preparation', description: 'The organization shall plan and prepare for managing information security incidents by defining processes, roles, and responsibilities.' },
  { id: 'A.5.25', title: 'Assessment and decision on information security events', description: 'The organization shall assess information security events and decide if they are to be categorized as incidents.' },
  { id: 'A.5.28', title: 'Collection of evidence', description: 'The organization shall establish and implement procedures for the identification, collection, acquisition, and preservation of evidence related to security events.' },
  { id: 'A.5.31', title: 'Legal, statutory, regulatory, and contractual requirements', description: 'Legal, statutory, regulatory, and contractual requirements relevant to information security shall be identified, documented, and kept up to date.' },
  { id: 'A.5.34', title: 'Privacy and protection of PII', description: 'The organization shall identify and meet requirements regarding preservation of privacy and protection of PII according to applicable laws.' },
  { id: 'A.6.3', title: 'Information security awareness, education, and training', description: 'Personnel and relevant interested parties shall receive appropriate awareness education and training in information security.' },
  { id: 'A.8.2', title: 'Privileged access rights', description: 'The allocation and use of privileged access rights shall be restricted and managed.' },
  { id: 'A.8.3', title: 'Information access restriction', description: 'Access to information and application system functions shall be restricted in accordance with the access control policy.' },
  { id: 'A.8.5', title: 'Secure authentication', description: 'Secure authentication technologies and procedures shall be implemented based on information access restrictions and the access control policy.' },
  { id: 'A.8.8', title: 'Management of technical vulnerabilities', description: 'Information about technical vulnerabilities shall be obtained, exposure evaluated, and appropriate measures taken.' },
  { id: 'A.8.9', title: 'Configuration management', description: 'Configurations, including security configurations, of hardware, software, services, and networks shall be established, documented, and monitored.' },
  { id: 'A.8.10', title: 'Information deletion', description: 'Information stored in information systems, devices, or in any other storage media shall be deleted when no longer required.' },
  { id: 'A.8.12', title: 'Data leakage prevention', description: 'Data leakage prevention measures shall be applied to systems, networks, and other devices that process, store, or transmit sensitive information.' },
  { id: 'A.8.13', title: 'Information backup', description: 'Backup copies of information, software, and systems shall be maintained and regularly tested in accordance with an agreed backup policy.' },
  { id: 'A.8.15', title: 'Logging', description: 'Logs that record activities, exceptions, faults, and other relevant events shall be produced, kept, and regularly reviewed.' },
  { id: 'A.8.16', title: 'Monitoring activities', description: 'Networks, systems, and applications shall be monitored for anomalous behavior and potential information security incidents.' },
  { id: 'A.8.20', title: 'Networks security', description: 'Networks and network devices shall be secured, managed, and controlled to protect information in systems and applications.' },
  { id: 'A.8.22', title: 'Segregation of networks', description: 'Groups of information services, users, and information systems shall be segregated in the organization\'s networks.' },
  { id: 'A.8.23', title: 'Web filtering', description: 'Access to external websites shall be managed to reduce exposure to malicious content.' },
  { id: 'A.8.24', title: 'Use of cryptography', description: 'Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.' },
  { id: 'A.8.25', title: 'Secure development life cycle', description: 'Rules for the secure development of software and systems shall be established and applied throughout the development life cycle.' },
  { id: 'A.8.26', title: 'Application security requirements', description: 'Information security requirements shall be identified, specified, and approved when developing or acquiring applications.' },
  { id: 'A.8.28', title: 'Secure coding', description: 'Secure coding principles shall be applied to software development to reduce the number of potential vulnerabilities.' },
  { id: 'A.8.29', title: 'Security testing in development and acceptance', description: 'Security testing processes shall be defined and implemented in the development life cycle.' },
];

const CIS_CONTROLS_V8 = [
  { id: 'CIS-1', title: 'Inventory and Control of Enterprise Assets', description: 'Actively manage all enterprise assets connected to the infrastructure to accurately know the totality of assets that need to be monitored and protected.' },
  { id: 'CIS-2', title: 'Inventory and Control of Software Assets', description: 'Actively manage all software on the network so that only authorized software is installed and executable, and unauthorized software is found and prevented.' },
  { id: 'CIS-3', title: 'Data Protection', description: 'Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.' },
  { id: 'CIS-4', title: 'Secure Configuration of Enterprise Assets and Software', description: 'Establish and maintain the secure configuration of enterprise assets and software.' },
  { id: 'CIS-5', title: 'Account Management', description: 'Use processes and tools to assign and manage authorization to credentials for user accounts, including administrator accounts and service accounts.' },
  { id: 'CIS-6', title: 'Access Control Management', description: 'Use processes and tools to create, assign, manage, and revoke access credentials and privileges for users, administrators, and service accounts.' },
  { id: 'CIS-7', title: 'Continuous Vulnerability Management', description: 'Develop a plan to continuously assess and track vulnerabilities on all enterprise assets to remediate and minimize the window of opportunity for attackers.' },
  { id: 'CIS-8', title: 'Audit Log Management', description: 'Collect, alert, review, and retain audit logs of events that could help detect, understand, or recover from an attack.' },
  { id: 'CIS-9', title: 'Email and Web Browser Protections', description: 'Improve protections and detections of threats from email and web vectors, as these are opportunities for attackers to manipulate human behavior.' },
  { id: 'CIS-10', title: 'Malware Defenses', description: 'Prevent or control the installation, spread, and execution of malicious applications, code, or scripts on enterprise assets.' },
  { id: 'CIS-11', title: 'Data Recovery', description: 'Establish and maintain data recovery practices sufficient to restore in-scope enterprise assets to a pre-incident and trusted state.' },
  { id: 'CIS-12', title: 'Network Infrastructure Management', description: 'Establish, implement, and actively manage network devices to prevent attackers from exploiting vulnerable network services and access points.' },
  { id: 'CIS-13', title: 'Network Monitoring and Defense', description: 'Operate processes and tooling to establish and maintain comprehensive network monitoring and defense against security threats.' },
  { id: 'CIS-14', title: 'Security Awareness and Skills Training', description: 'Establish and maintain a security awareness program to influence behavior among the workforce to be security conscious.' },
  { id: 'CIS-15', title: 'Service Provider Management', description: 'Develop a process to evaluate service providers that hold sensitive data or are responsible for critical IT platforms.' },
  { id: 'CIS-16', title: 'Application Software Security', description: 'Manage the security life cycle of in-house developed, hosted, or acquired software to prevent, detect, and remediate security weaknesses.' },
  { id: 'CIS-17', title: 'Incident Response Management', description: 'Establish a program to develop and maintain an incident response capability to prepare for, detect, and quickly respond to an attack.' },
  { id: 'CIS-18', title: 'Penetration Testing', description: 'Test the effectiveness and resilience of enterprise assets through simulating the objectives and actions of an attacker.' },
];

// Maps each STRIDE category to the most relevant controls across all three frameworks
const STRIDE_COMPLIANCE_MAP = {
  spoofing: {
    nist: ['AC-2', 'AC-3', 'AC-7', 'AC-17', 'IA-2', 'IA-4', 'IA-5', 'IA-8', 'IA-11', 'SC-8', 'SC-23'],
    iso: ['A.5.15', 'A.5.16', 'A.5.17', 'A.8.5', 'A.8.20'],
    cis: ['CIS-5', 'CIS-6', 'CIS-9'],
    rationale: 'Spoofing threats are primarily mitigated through strong identification, authentication, and session-authenticity controls that prevent an attacker from successfully impersonating a legitimate identity.',
  },
  tampering: {
    nist: ['AC-4', 'AC-6', 'CM-2', 'CM-6', 'SC-8', 'SC-12', 'SC-13', 'SC-28', 'SI-2', 'SI-7', 'SI-10', 'SR-3'],
    iso: ['A.5.19', 'A.8.9', 'A.8.24', 'A.8.25', 'A.8.28', 'A.8.29'],
    cis: ['CIS-3', 'CIS-4', 'CIS-16'],
    rationale: 'Tampering threats are mitigated through integrity controls -- cryptographic protection, configuration management, input validation, and secure development practices that prevent unauthorized modification of data and code.',
  },
  repudiation: {
    nist: ['AU-2', 'AU-3', 'AU-6', 'AU-9', 'AU-10', 'AU-11', 'AU-12', 'IA-2'],
    iso: ['A.5.28', 'A.8.15', 'A.8.16'],
    cis: ['CIS-8'],
    rationale: 'Repudiation threats are mitigated through comprehensive, tamper-evident audit logging that individually attributes actions to authenticated identities and preserves non-repudiable evidence.',
  },
  information_disclosure: {
    nist: ['AC-3', 'AC-4', 'SC-7', 'SC-8', 'SC-13', 'SC-28', 'RA-5'],
    iso: ['A.5.34', 'A.8.3', 'A.8.10', 'A.8.12', 'A.8.24'],
    cis: ['CIS-3', 'CIS-13'],
    rationale: 'Information disclosure threats are mitigated through confidentiality controls -- encryption, access restriction, data loss prevention, and boundary protection that limit exposure of sensitive data.',
  },
  denial_of_service: {
    nist: ['SC-5', 'SC-7', 'CP-9', 'CP-10', 'SI-4'],
    iso: ['A.8.13', 'A.8.16', 'A.8.20', 'A.8.22'],
    cis: ['CIS-11', 'CIS-12', 'CIS-13'],
    rationale: 'Denial of service threats are mitigated through availability controls -- resilient architecture, DoS protection, network monitoring, backup, and recovery capabilities.',
  },
  elevation_of_privilege: {
    nist: ['AC-2', 'AC-3', 'AC-6', 'AC-25', 'CM-7', 'RA-3', 'SA-11', 'SA-15'],
    iso: ['A.5.18', 'A.8.2', 'A.8.8', 'A.8.26', 'A.8.29'],
    cis: ['CIS-4', 'CIS-6', 'CIS-7', 'CIS-16', 'CIS-18'],
    rationale: 'Elevation of privilege threats are mitigated through authorization controls -- least privilege, privileged access management, vulnerability management, and secure application design that prevent unauthorized capability gain.',
  },
};

/* ============================================================================
   SECTION 13: SECURITY REQUIREMENTS TEMPLATES
   ========================================================================== */

const SECURITY_REQUIREMENTS_TEMPLATES = {
  spoofing: [
    { id: 'REQ-SP-01', requirement: 'The system shall require multi-factor authentication for all user accounts with administrative or privileged access.', priority: 'Critical', verification: 'Manual test: attempt admin login with password only; confirm MFA challenge is enforced.' },
    { id: 'REQ-SP-02', requirement: 'The system shall generate session identifiers using a cryptographically secure random number generator with a minimum of 128 bits of entropy.', priority: 'High', verification: 'Code review of session ID generation library and configuration.' },
    { id: 'REQ-SP-03', requirement: 'The system shall regenerate the session identifier immediately upon a successful authentication event.', priority: 'High', verification: 'Dynamic test: capture pre-auth and post-auth session cookies and confirm they differ.' },
    { id: 'REQ-SP-04', requirement: 'The system shall enforce SPF, DKIM, and DMARC with a reject or quarantine policy on all outbound mail domains.', priority: 'Medium', verification: 'DNS record inspection and mail authentication test tools.' },
    { id: 'REQ-SP-05', requirement: 'The system shall validate the signature, issuer, audience, and expiry of every authentication token on every request.', priority: 'Critical', verification: 'Code review of token validation middleware; test with forged/expired tokens.' },
    { id: 'REQ-SP-06', requirement: 'The system shall use mutual TLS or signed service tokens for all internal service-to-service authentication.', priority: 'High', verification: 'Architecture review and network traffic inspection between services.' },
    { id: 'REQ-SP-07', requirement: 'The system shall enforce PKCE for all public/native OAuth 2.0 clients.', priority: 'High', verification: 'Review OAuth client registration and authorization code flow implementation.' },
    { id: 'REQ-SP-08', requirement: 'The system shall never accept authentication tokens signed with the "none" algorithm or an unexpected signing algorithm.', priority: 'Critical', verification: 'Test with a token using alg:none and confirm rejection.' },
    { id: 'REQ-SP-09', requirement: 'The system shall bind password-reset tokens to a single use, a short expiry window, and cryptographically random generation.', priority: 'High', verification: 'Test reset token reuse and predictability.' },
    { id: 'REQ-SP-10', requirement: 'The system shall disable legacy authentication protocols that do not support multi-factor authentication.', priority: 'Medium', verification: 'Inventory all authentication entry points and confirm none bypass MFA enforcement.' },
    { id: 'REQ-SP-11', requirement: 'The system shall verify webhook payload authenticity using HMAC signatures and timestamp validation before processing.', priority: 'High', verification: 'Test with an unsigned or replayed webhook payload and confirm rejection.' },
    { id: 'REQ-SP-12', requirement: 'The system shall issue unique, individually revocable credentials to each integration partner rather than shared keys.', priority: 'Medium', verification: 'Review API key issuance process and credential inventory.' },
  ],
  tampering: [
    { id: 'REQ-TA-01', requirement: 'The system shall use parameterized queries or an ORM with built-in escaping for all database access involving user input.', priority: 'Critical', verification: 'Static code analysis (SAST) and manual injection testing.' },
    { id: 'REQ-TA-02', requirement: 'The system shall re-validate and re-derive all security-relevant values (price, role, quantity) server-side, independent of client-submitted data.', priority: 'Critical', verification: 'Dynamic test: modify client-side request parameters and confirm server-side rejection or correction.' },
    { id: 'REQ-TA-03', requirement: 'The system shall digitally sign all software update packages and verify signatures prior to installation.', priority: 'High', verification: 'Code review of update mechanism; attempt installation of an unsigned/modified package.' },
    { id: 'REQ-TA-04', requirement: 'The system shall forward audit logs to a separate, append-only storage system in near real time.', priority: 'High', verification: 'Architecture review of log pipeline; confirm source systems lack delete permission on the log store.' },
    { id: 'REQ-TA-05', requirement: 'The system shall disable external entity and DTD processing in all XML parsers.', priority: 'High', verification: 'Test with a crafted XXE payload and confirm no external entity resolution occurs.' },
    { id: 'REQ-TA-06', requirement: 'The system shall sign container images prior to registry push and enforce admission control that rejects unsigned images.', priority: 'Medium', verification: 'Attempt to deploy an unsigned image and confirm rejection by the admission controller.' },
    { id: 'REQ-TA-07', requirement: 'The system shall enforce branch protection rules disallowing force-pushes and requiring signed, reviewed commits on protected branches.', priority: 'Medium', verification: 'Repository configuration review.' },
    { id: 'REQ-TA-08', requirement: 'The system shall enforce entitlement and authorization checks server-side for all premium or gated functionality.', priority: 'High', verification: 'Test by modifying client-side local storage/state and confirming server-side enforcement.' },
    { id: 'REQ-TA-09', requirement: 'The system shall use safe object-merge utilities that block prototype-chain key assignment (__proto__, constructor, prototype).', priority: 'Medium', verification: 'Static code analysis and prototype pollution payload testing.' },
    { id: 'REQ-TA-10', requirement: 'The system shall include all security-relevant parameters (expiry, scope, resource path) within the signed payload of any pre-signed URL.', priority: 'Medium', verification: 'Test modification of unsigned URL parameters and confirm signature invalidation.' },
    { id: 'REQ-TA-11', requirement: 'The system shall store backups in immutable, access-controlled storage and verify integrity hashes prior to restore.', priority: 'High', verification: 'Review backup storage configuration and restore procedure documentation.' },
    { id: 'REQ-TA-12', requirement: 'The system shall use atomic transactions or optimistic locking for all state-changing financial or inventory operations.', priority: 'High', verification: 'Concurrency testing with simultaneous conflicting requests.' },
  ],
  repudiation: [
    { id: 'REQ-RE-01', requirement: 'The system shall log the authenticated identity, action, target resource, timestamp, and outcome for every security-relevant action.', priority: 'High', verification: 'Log format review against a defined logging standard.' },
    { id: 'REQ-RE-02', requirement: 'The system shall eliminate shared administrative accounts in favor of individually attributable credentials with privilege elevation.', priority: 'High', verification: 'Account inventory review.' },
    { id: 'REQ-RE-03', requirement: 'The system shall synchronize all host clocks via NTP and alert on clock drift exceeding a defined threshold.', priority: 'Medium', verification: 'Configuration review and drift monitoring dashboard inspection.' },
    { id: 'REQ-RE-04', requirement: 'The system shall retain audit logs for a period meeting the longest applicable legal, contractual, or regulatory requirement.', priority: 'Medium', verification: 'Retention policy review against compliance obligations matrix.' },
    { id: 'REQ-RE-05', requirement: 'The system shall log every access to customer data made through internal support or administrative tooling.', priority: 'High', verification: 'Test read-only data access through internal tools and confirm a corresponding log entry is created.' },
    { id: 'REQ-RE-06', requirement: 'The system shall grant application service accounts append-only permissions on log storage, with delete/modify rights restricted to a separate security role.', priority: 'High', verification: 'IAM policy review of log storage permissions.' },
    { id: 'REQ-RE-07', requirement: 'The system shall bind privileged approval workflows to an MFA-backed, individually authenticated approver identity.', priority: 'Medium', verification: 'Review of change-management/approval system configuration.' },
    { id: 'REQ-RE-08', requirement: 'The system shall record session activity (keystroke or command logging) for privileged access to critical systems via jump hosts.', priority: 'Medium', verification: 'Review of bastion host session recording configuration.' },
    { id: 'REQ-RE-09', requirement: 'The system shall enable database-native audit logging independent of the application logging layer for direct data-store access.', priority: 'Medium', verification: 'Database audit configuration review.' },
    { id: 'REQ-RE-10', requirement: 'The system shall generate independent, server-side transaction confirmations that a user cannot unilaterally delete or alter.', priority: 'Low', verification: 'Test deletion of an in-app transaction record and confirm the independent confirmation record persists.' },
    { id: 'REQ-RE-11', requirement: 'The system shall monitor expected log volume per source and alert on unexpected gaps in log forwarding.', priority: 'Medium', verification: 'Review SIEM/log pipeline heartbeat and gap-alerting configuration.' },
    { id: 'REQ-RE-12', requirement: 'The system shall tag impersonated support-login session actions with both the acting employee identity and the target user identity.', priority: 'High', verification: 'Test impersonation feature and confirm dual-identity logging.' },
  ],
  information_disclosure: [
    { id: 'REQ-ID-01', requirement: 'The system shall default all cloud storage buckets and object stores to private access and automatically scan for public exposure.', priority: 'Critical', verification: 'Automated cloud security posture scan.' },
    { id: 'REQ-ID-02', requirement: 'The system shall return only the specific data fields the requesting client role is authorized to receive, not the full internal object.', priority: 'High', verification: 'API response review across different authorization levels.' },
    { id: 'REQ-ID-03', requirement: 'The system shall return generic error messages to clients in production; detailed error information shall be logged server-side only.', priority: 'Medium', verification: 'Trigger unhandled exceptions and inspect client-facing error content.' },
    { id: 'REQ-ID-04', requirement: 'The system shall encrypt sensitive data at rest, including backups and data warehouse copies, using keys managed separately via a KMS.', priority: 'Critical', verification: 'Encryption configuration review and key management architecture review.' },
    { id: 'REQ-ID-05', requirement: 'The system shall return identical responses and timing for both valid and invalid usernames during authentication-related flows.', priority: 'Medium', verification: 'Timing analysis and response comparison test across valid/invalid accounts.' },
    { id: 'REQ-ID-06', requirement: 'The system shall implement log scrubbing to redact known secret and PII patterns before log persistence.', priority: 'High', verification: 'Trigger events containing test secrets and confirm redaction in stored logs.' },
    { id: 'REQ-ID-07', requirement: 'The system shall exclude source maps and debug tooling from production builds.', priority: 'Medium', verification: 'Production build artifact inspection.' },
    { id: 'REQ-ID-08', requirement: 'The system shall disable GraphQL introspection in production environments.', priority: 'Medium', verification: 'Attempt an introspection query against the production endpoint.' },
    { id: 'REQ-ID-09', requirement: 'The system shall use an explicit allow-list of trusted origins for CORS and never combine wildcard origins with credentialed requests.', priority: 'High', verification: 'CORS configuration review and cross-origin request testing.' },
    { id: 'REQ-ID-10', requirement: 'The system shall set Cache-Control: no-store on all responses containing sensitive or personalized data.', priority: 'Medium', verification: 'Response header inspection for authenticated/personalized endpoints.' },
    { id: 'REQ-ID-11', requirement: 'The system shall enforce object-level authorization checks on every endpoint that accepts a client-supplied resource identifier.', priority: 'Critical', verification: 'IDOR testing by modifying resource identifiers across accounts.' },
    { id: 'REQ-ID-12', requirement: 'The system shall apply role-based field masking in internal support and administrative tooling based on demonstrated need.', priority: 'Medium', verification: 'Review internal tool data display against role-based access matrix.' },
  ],
  denial_of_service: [
    { id: 'REQ-DO-01', requirement: 'The system shall enforce rate limiting per user, API key, and IP address on all public-facing endpoints.', priority: 'High', verification: 'Load test exceeding defined rate limits and confirm throttling behavior.' },
    { id: 'REQ-DO-02', requirement: 'The system shall deploy a DDoS scrubbing service, CDN, or anycast network in front of all internet-facing infrastructure.', priority: 'High', verification: 'Architecture review of edge network configuration.' },
    { id: 'REQ-DO-03', requirement: 'The system shall review and remediate regular expressions applied to user input for catastrophic backtracking risk.', priority: 'Medium', verification: 'Static analysis of regex patterns and adversarial input testing.' },
    { id: 'REQ-DO-04', requirement: 'The system shall enforce maximum size and nesting-depth limits on JSON, XML, and YAML payload parsing.', priority: 'Medium', verification: 'Test with deeply nested and oversized payloads.' },
    { id: 'REQ-DO-05', requirement: 'The system shall use progressive delays or risk-based throttling for account lockout rather than permanent hard lockouts.', priority: 'Medium', verification: 'Test repeated failed login attempts and confirm lockout behavior does not permanently deny legitimate access.' },
    { id: 'REQ-DO-06', requirement: 'The system shall set aggressive timeouts and circuit breakers on all outbound calls to external dependencies.', priority: 'Medium', verification: 'Fault-injection testing simulating slow/unresponsive dependencies.' },
    { id: 'REQ-DO-07', requirement: 'The system shall enforce mandatory pagination and asynchronous processing for bulk data export operations.', priority: 'Medium', verification: 'Attempt an unbounded export request and confirm enforced limits.' },
    { id: 'REQ-DO-08', requirement: 'The system shall implement query complexity scoring and depth limits for GraphQL APIs.', priority: 'High', verification: 'Submit a deeply nested/complex query and confirm rejection or throttling.' },
    { id: 'REQ-DO-09', requirement: 'The system shall configure autoscaling with defined upper bounds and cost/anomaly alerting.', priority: 'Medium', verification: 'Review autoscaling configuration and alert thresholds.' },
    { id: 'REQ-DO-10', requirement: 'The system shall isolate database and thread-pool resources per critical workload to prevent starvation from a single noisy consumer.', priority: 'Medium', verification: 'Architecture review of resource pool isolation (bulkheads).' },
    { id: 'REQ-DO-11', requirement: 'The system shall implement dead-letter queues and maximum redelivery limits for asynchronous message processing.', priority: 'Medium', verification: 'Test with a malformed message and confirm it is isolated rather than looping indefinitely.' },
    { id: 'REQ-DO-12', requirement: 'The system shall enforce per-tenant queue quotas and priority lanes for background job processing.', priority: 'Low', verification: 'Load test one tenant\'s queue usage and confirm isolation from other tenants.' },
  ],
  elevation_of_privilege: [
    { id: 'REQ-EP-01', requirement: 'The system shall enforce authorization checks server-side on every request, independent of UI visibility or client-side state.', priority: 'Critical', verification: 'Direct API testing of privileged endpoints bypassing the UI.' },
    { id: 'REQ-EP-02', requirement: 'The system shall use explicit allow-lists of writable fields for all update operations rather than binding entire request bodies to internal models.', priority: 'High', verification: 'Mass-assignment testing by submitting unexpected privileged fields.' },
    { id: 'REQ-EP-03', requirement: 'The system shall scope IAM roles and service accounts to least privilege for their specific function, reviewed periodically.', priority: 'High', verification: 'IAM policy review for wildcard permissions and unused broad grants.' },
    { id: 'REQ-EP-04', requirement: 'The system shall disable or rotate all default and unused administrative accounts.', priority: 'Critical', verification: 'Account inventory audit for default/unused administrative credentials.' },
    { id: 'REQ-EP-05', requirement: 'The system shall avoid native deserialization of untrusted input, using schema-validated formats with strict typing instead.', priority: 'Critical', verification: 'Static code analysis for unsafe deserialization patterns.' },
    { id: 'REQ-EP-06', requirement: 'The system shall require separate, independent approval from the requester for all high-impact privileged changes.', priority: 'Medium', verification: 'Change-management workflow review for separation of duties.' },
    { id: 'REQ-EP-07', requirement: 'The system shall adopt just-in-time privileged access management with time-bound, audited elevation instead of standing admin rights.', priority: 'Medium', verification: 'Review of PAM tooling configuration and standing-privilege inventory.' },
    { id: 'REQ-EP-08', requirement: 'The system shall enforce tenant-scoping at the data-access layer for every query in multi-tenant environments.', priority: 'Critical', verification: 'Automated cross-tenant isolation testing.' },
    { id: 'REQ-EP-09', requirement: 'The system shall apply seccomp/AppArmor profiles and rootless container execution, patched promptly against known escape vulnerabilities.', priority: 'High', verification: 'Container security configuration review and patch SLA compliance check.' },
    { id: 'REQ-EP-10', requirement: 'The system shall sandbox third-party plugins and extensions with capability-based permission scopes.', priority: 'Medium', verification: 'Review plugin execution architecture for privilege isolation.' },
    { id: 'REQ-EP-11', requirement: 'The system shall time-limit break-glass emergency access and require a mandatory post-use review for every invocation.', priority: 'Medium', verification: 'Review break-glass access logs and confirm automatic expiry and review completion.' },
    { id: 'REQ-EP-12', requirement: 'The system shall require step-up re-authentication immediately before any privilege-granting action.', priority: 'High', verification: 'Test privilege-granting actions with a hijacked/replayed session and confirm re-authentication is enforced.' },
  ],
};

/* ============================================================================
   SECTION 14: ASSET INVENTORY TEMPLATE FIELDS
   ========================================================================== */

const ASSET_TYPES = ['Application', 'API / Service', 'Database', 'Server / Host', 'Network Device', 'Cloud Resource', 'Mobile App', 'IoT / Embedded Device', 'Data Store', 'Third-Party Integration', 'Credential / Secret', 'Documentation / IP'];
const ASSET_SENSITIVITY_LEVELS = ['Public', 'Internal', 'Confidential', 'Restricted'];
const ASSET_CIA_LEVELS = ['Low', 'Medium', 'High'];

const ASSET_INVENTORY_FIELDS = [
  { key: 'name', label: 'Asset Name', type: 'text', required: true, help: 'A clear, unique name identifying the asset.' },
  { key: 'type', label: 'Asset Type', type: 'select', options: ASSET_TYPES, required: true, help: 'The category of asset.' },
  { key: 'owner', label: 'Owner', type: 'text', required: true, help: 'The individual or team accountable for this asset.' },
  { key: 'description', label: 'Description', type: 'textarea', required: false, help: 'What the asset does and why it exists.' },
  { key: 'sensitivity', label: 'Data Sensitivity', type: 'select', options: ASSET_SENSITIVITY_LEVELS, required: true, help: 'The classification level of data associated with this asset.' },
  { key: 'confidentiality', label: 'Confidentiality Requirement', type: 'select', options: ASSET_CIA_LEVELS, required: true, help: 'How damaging would unauthorized disclosure be?' },
  { key: 'integrity', label: 'Integrity Requirement', type: 'select', options: ASSET_CIA_LEVELS, required: true, help: 'How damaging would unauthorized modification be?' },
  { key: 'availability', label: 'Availability Requirement', type: 'select', options: ASSET_CIA_LEVELS, required: true, help: 'How damaging would loss of access be?' },
  { key: 'location', label: 'Location / Hosting', type: 'text', required: false, help: 'Where the asset is deployed (cloud region, data center, on-device).' },
  { key: 'dependencies', label: 'Dependencies', type: 'textarea', required: false, help: 'Other assets or services this asset depends on.' },
  { key: 'threats', label: 'Linked Threats', type: 'textarea', required: false, help: 'Known or identified threats affecting this asset.' },
  { key: 'notes', label: 'Notes', type: 'textarea', required: false, help: 'Any additional context.' },
];

/* ============================================================================
   SECTION 15: RISK MATRIX DEFAULT CONFIGURATION
   ========================================================================== */

const RISK_MATRIX_DEFAULT_LIKELIHOOD = [
  { level: 1, label: 'Rare', description: 'May occur only in exceptional circumstances; less than once every few years.' },
  { level: 2, label: 'Unlikely', description: 'Could occur at some point; roughly once every 1-2 years.' },
  { level: 3, label: 'Possible', description: 'Might occur at some point; roughly once per year.' },
  { level: 4, label: 'Likely', description: 'Will probably occur; several times per year.' },
  { level: 5, label: 'Almost Certain', description: 'Expected to occur in most circumstances; monthly or more frequently.' },
];

const RISK_MATRIX_DEFAULT_IMPACT = [
  { level: 1, label: 'Negligible', description: 'Minimal impact on operations, finances, or reputation; easily absorbed.' },
  { level: 2, label: 'Minor', description: 'Limited impact requiring some management attention and minor cost.' },
  { level: 3, label: 'Moderate', description: 'Significant impact requiring management response and meaningful cost.' },
  { level: 4, label: 'Major', description: 'Severe impact with substantial financial, operational, or reputational damage.' },
  { level: 5, label: 'Catastrophic', description: 'Existential impact threatening the viability of the business or safety of individuals.' },
];

function riskMatrixCellRating(likelihood, impact) {
  const score = likelihood * impact;
  if (score >= 20) return { label: 'Critical', color: '#ff2e63' };
  if (score >= 12) return { label: 'High', color: '#ff5f56' };
  if (score >= 6) return { label: 'Medium', color: '#ffbd2e' };
  return { label: 'Low', color: '#27c93f' };
}

/* ============================================================================
   SECTION 16: GLOBAL STATE
   ========================================================================== */

const tmState = {
  activeTab: 'overview',
  stride: {
    checked: {},   // questionId -> boolean
    notes: {},     // questionId -> string
  },
  dread: {
    entries: [],   // { id, name, scores: { damage, reproducibility, exploitability, affected_users, discoverability } }
    weights: { damage: 1, reproducibility: 1, exploitability: 1, affected_users: 1, discoverability: 1 },
  },
  attackTree: {
    goal: 'Compromise the target system',
    nodes: [
      { id: 'root', parentId: null, label: 'Compromise the target system', probability: 0.5, gate: 'OR' },
    ],
  },
  linddun: {
    checked: {},
  },
  threatLibrary: {
    filterCategory: 'all',
    filterSeverity: 'all',
    search: '',
    selected: {}, // threatId -> true
  },
  assets: [],
  riskMatrix: {
    likelihood: tmClone(RISK_MATRIX_DEFAULT_LIKELIHOOD),
    impact: tmClone(RISK_MATRIX_DEFAULT_IMPACT),
    risks: [], // { id, name, likelihood, impact, notes }
  },
  securityRequirements: {
    selectedThreatIds: {},
  },
  compliance: {
    selectedCategory: 'spoofing',
    framework: 'nist',
  },
  report: {
    projectName: 'Untitled System',
    author: '',
    version: '1.0',
    scope: '',
  },
};

function tmInjectStyles() {
  if (document.getElementById('tm-styles')) return;
  const style = document.createElement('style');
  style.id = 'tm-styles';
  style.textContent = `
    .tm-wrap { display: flex; flex-direction: column; gap: 20px; }
    .tm-grid { display: grid; gap: 16px; }
    .tm-grid-2 { grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }
    .tm-grid-3 { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
    .tm-grid-6 { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
    .tm-section-nav { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 4px; }
    .tm-badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 600; letter-spacing: .03em; text-transform: uppercase; border: 1px solid rgba(255,255,255,.15); }
    .tm-badge-critical { color: #ff2e63; border-color: #ff2e63; }
    .tm-badge-high { color: #ff5f56; border-color: #ff5f56; }
    .tm-badge-medium { color: #ffbd2e; border-color: #ffbd2e; }
    .tm-badge-low { color: #27c93f; border-color: #27c93f; }
    .tm-badge-info { color: #8b98a5; border-color: #8b98a5; }
    .tm-threat-card { border: 1px solid rgba(255,255,255,.08); border-radius: 10px; padding: 14px 16px; background: rgba(255,255,255,.02); }
    .tm-threat-card h4 { margin: 0 0 6px 0; font-size: 15px; }
    .tm-threat-meta { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; flex-wrap: wrap; }
    .tm-threat-field { margin: 6px 0; font-size: 13px; line-height: 1.5; }
    .tm-threat-field b { opacity: .75; margin-right: 4px; }
    .tm-checklist-item { display: flex; gap: 10px; align-items: flex-start; padding: 10px 0; border-bottom: 1px dashed rgba(255,255,255,.08); }
    .tm-checklist-item input[type=checkbox] { margin-top: 3px; width: 16px; height: 16px; flex-shrink: 0; }
    .tm-checklist-q { font-size: 13.5px; }
    .tm-checklist-g { font-size: 12px; opacity: .65; margin-top: 3px; }
    .tm-slider-row { display: flex; flex-direction: column; gap: 4px; margin-bottom: 16px; }
    .tm-slider-row label { font-size: 13px; font-weight: 600; display: flex; justify-content: space-between; }
    .tm-slider-row input[type=range] { width: 100%; accent-color: #ff2e63; }
    .tm-slider-level { font-size: 11.5px; opacity: .65; }
    .tm-score-ring { display: flex; align-items: center; justify-content: center; flex-direction: column; width: 120px; height: 120px; border-radius: 50%; border: 6px solid rgba(255,255,255,.1); margin: 0 auto; }
    .tm-score-num { font-size: 30px; font-weight: 800; font-family: monospace; }
    .tm-score-lbl { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; opacity: .7; }
    .tm-tree-node { border: 1px solid rgba(255,255,255,.12); border-radius: 8px; padding: 8px 12px; background: rgba(255,255,255,.03); margin-bottom: 6px; }
    .tm-tree-children { margin-left: 28px; border-left: 2px dashed rgba(255,255,255,.12); padding-left: 16px; }
    .tm-tree-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .tm-tree-row input[type=text] { flex: 1; min-width: 160px; background: rgba(0,0,0,.3); border: 1px solid rgba(255,255,255,.15); color: inherit; padding: 5px 8px; border-radius: 6px; font-size: 13px; }
    .tm-tree-row input[type=number] { width: 70px; background: rgba(0,0,0,.3); border: 1px solid rgba(255,255,255,.15); color: inherit; padding: 5px 8px; border-radius: 6px; font-size: 13px; }
    .tm-tree-row select { background: rgba(0,0,0,.3); border: 1px solid rgba(255,255,255,.15); color: inherit; padding: 5px 8px; border-radius: 6px; font-size: 13px; }
    .tm-matrix-table { border-collapse: collapse; width: 100%; }
    .tm-matrix-table th, .tm-matrix-table td { border: 1px solid rgba(255,255,255,.1); padding: 8px; text-align: center; font-size: 12.5px; }
    .tm-matrix-cell { font-weight: 700; cursor: default; }
    .tm-form-field { display: flex; flex-direction: column; gap: 4px; margin-bottom: 12px; }
    .tm-form-field label { font-size: 12.5px; font-weight: 600; opacity: .85; }
    .tm-form-field input[type=text], .tm-form-field textarea, .tm-form-field select { background: rgba(0,0,0,.3); border: 1px solid rgba(255,255,255,.15); color: inherit; padding: 7px 10px; border-radius: 6px; font-size: 13px; font-family: inherit; }
    .tm-form-field textarea { min-height: 60px; resize: vertical; }
    .tm-table-wrap { overflow-x: auto; }
    .tm-table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
    .tm-table th, .tm-table td { border: 1px solid rgba(255,255,255,.08); padding: 8px 10px; text-align: left; vertical-align: top; }
    .tm-table th { background: rgba(255,255,255,.04); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; opacity: .8; }
    .tm-pill-toggle { display: inline-flex; gap: 6px; flex-wrap: wrap; }
    .tm-pill { padding: 5px 12px; border-radius: 4px; border: 1px solid rgba(255,255,255,.15); font-size: 12px; cursor: pointer; background: transparent; color: inherit; }
    .tm-pill.active { background: rgba(255,46,99,.15); border-color: #ff2e63; color: #ff2e63; }
    .tm-progress-bar { height: 6px; border-radius: 4px; background: rgba(255,255,255,.08); overflow: hidden; }
    .tm-progress-fill { height: 100%; background: linear-gradient(90deg, #ff2e63, #ff5f56); }
    .tm-empty { padding: 32px 16px; text-align: center; opacity: .6; font-size: 13px; }
    .tm-flex-between { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
    .tm-stage-card { border: 1px solid rgba(255,255,255,.08); border-radius: 10px; padding: 16px 18px; background: rgba(255,255,255,.02); margin-bottom: 14px; }
    .tm-stage-num { display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; border-radius: 50%; background: rgba(255,46,99,.15); color: #ff2e63; font-weight: 700; font-size: 13px; margin-right: 8px; }
    .tm-two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    @media (max-width: 720px) { .tm-two-col { grid-template-columns: 1fr; } }
    .tm-list-compact { margin: 6px 0 0 0; padding-left: 18px; font-size: 12.5px; line-height: 1.6; }
    .tm-report-preview { white-space: pre-wrap; font-family: monospace; font-size: 12px; line-height: 1.6; background: rgba(0,0,0,.35); border: 1px solid rgba(255,255,255,.1); border-radius: 8px; padding: 16px; max-height: 480px; overflow-y: auto; }
  `;
  document.head.appendChild(style);
}

/* ============================================================================
   SECTION 17: MAIN ENTRY POINT AND TAB WIRING
   ========================================================================== */

const TM_TABS = [
  { key: 'overview', label: 'Overview' },
  { key: 'stride', label: 'STRIDE' },
  { key: 'dread', label: 'DREAD' },
  { key: 'attacktree', label: 'Attack Trees' },
  { key: 'pasta', label: 'PASTA' },
  { key: 'linddun', label: 'LINDDUN' },
  { key: 'dfd', label: 'Data Flow Diagrams' },
  { key: 'library', label: 'Threat Library' },
  { key: 'assets', label: 'Asset Inventory' },
  { key: 'riskmatrix', label: 'Risk Matrix' },
  { key: 'requirements', label: 'Requirements' },
  { key: 'compliance', label: 'Compliance' },
  { key: 'report', label: 'Report' },
];

export function renderThreatModel(main) {
  tmInjectStyles();
  main.innerHTML = `
    <div class="tm-wrap">
      <div>
        <div class="eyebrow">Threat Modeling</div>
        <h1 class="pg-h1">Threat Modeling Workbench</h1>
        <p class="pg-sub">STRIDE, DREAD, PASTA, LINDDUN, attack trees, a 260+ item threat library, asset inventory, risk matrix, security requirements, and compliance mapping (NIST 800-53 / ISO 27001 / CIS Controls) -- all in one interactive workbench.</p>
      </div>
      <div class="tab-bar" id="tm-tab-bar"></div>
      <div id="tm-tab-content"></div>
    </div>
  `;

  const tabBar = main.querySelector('#tm-tab-bar');
  const content = main.querySelector('#tm-tab-content');

  function renderTabBar() {
    tabBar.innerHTML = TM_TABS.map((t) => `<button type="button" class="tab${t.key === tmState.activeTab ? ' active' : ''}" data-tab="${t.key}">${tmEsc(t.label)}</button>`).join('');
    tabBar.querySelectorAll('[data-tab]').forEach((btn) => {
      btn.addEventListener('click', () => {
        tmState.activeTab = btn.getAttribute('data-tab');
        renderTabBar();
        renderTabContent();
      });
    });
  }

  function renderTabContent() {
    content.innerHTML = '';
    switch (tmState.activeTab) {
      case 'overview': renderOverviewSection(content); break;
      case 'stride': renderStrideSection(content); break;
      case 'dread': renderDreadSection(content); break;
      case 'attacktree': renderAttackTreeSection(content); break;
      case 'pasta': renderPastaSection(content); break;
      case 'linddun': renderLinddunSection(content); break;
      case 'dfd': renderDfdSection(content); break;
      case 'library': renderThreatLibrarySection(content); break;
      case 'assets': renderAssetInventorySection(content); break;
      case 'riskmatrix': renderRiskMatrixSection(content); break;
      case 'requirements': renderSecurityRequirementsSection(content); break;
      case 'compliance': renderComplianceSection(content); break;
      case 'report': renderReportSection(content); break;
      default: renderOverviewSection(content);
    }
  }

  renderTabBar();
  renderTabContent();
}

/* ============================================================================
   SECTION 18: OVERVIEW SECTION
   ========================================================================== */

const TM_METHODOLOGY_SUMMARIES = [
  { key: 'stride', name: 'STRIDE', by: 'Microsoft', focus: 'Software / system-centric', best: 'Fast, developer-friendly threat categorization during design reviews.', tab: 'stride' },
  { key: 'dread', name: 'DREAD', by: 'Microsoft (legacy)', focus: 'Risk scoring', best: 'Quick relative-priority scoring once threats have already been identified.', tab: 'dread' },
  { key: 'pasta', name: 'PASTA', by: 'VerSprite', focus: 'Risk-centric, business-aligned', best: 'Enterprise threat modeling that must tie technical risk to business impact.', tab: 'pasta' },
  { key: 'linddun', name: 'LINDDUN', by: 'KU Leuven', focus: 'Privacy-centric', best: 'Identifying privacy threats and GDPR/CCPA-relevant risks in data flows.', tab: 'linddun' },
  { key: 'attacktree', name: 'Attack Trees', by: 'Bruce Schneier', focus: 'Goal-oriented decomposition', best: 'Modeling the specific paths an attacker could take toward one high-value objective.', tab: 'attacktree' },
  { key: 'dfd', name: 'Data Flow Diagrams', by: 'Structured analysis / Microsoft SDL', focus: 'Structural / architectural', best: 'The shared structural foundation nearly every other methodology threats against.', tab: 'dfd' },
];

function tmCountStrideChecked() {
  const total = STRIDE_CATEGORIES.reduce((s, c) => s + c.questions.length, 0);
  const done = Object.values(tmState.stride.checked).filter(Boolean).length;
  return { done, total };
}

function tmCountLinddunChecked() {
  const total = LINDDUN_CATEGORIES.length * 1;
  const done = Object.keys(tmState.linddun.checked).filter((k) => tmState.linddun.checked[k]).length;
  return { done, total: LINDDUN_CATEGORIES.reduce((s) => s + 1, 0) || total };
}

function renderOverviewSection(container) {
  const stride = tmCountStrideChecked();
  const threatCount = Object.values(THREAT_LIBRARY).reduce((s, arr) => s + arr.length, 0);
  const selectedThreats = Object.values(tmState.threatLibrary.selected).filter(Boolean).length;
  const assetCount = tmState.assets.length;
  const riskCount = tmState.riskMatrix.risks.length;
  const dreadCount = tmState.dread.entries.length;

  container.innerHTML = `
    <div class="tm-grid tm-grid-6" style="margin-bottom:8px;">
      <div class="stat"><div class="stat-n">${threatCount}</div><div class="stat-l">Threats in Library</div></div>
      <div class="stat"><div class="stat-n">${stride.done}/${stride.total}</div><div class="stat-l">STRIDE Questions Reviewed</div></div>
      <div class="stat"><div class="stat-n">${dreadCount}</div><div class="stat-l">DREAD Scored Threats</div></div>
      <div class="stat"><div class="stat-n">${assetCount}</div><div class="stat-l">Assets Inventoried</div></div>
      <div class="stat"><div class="stat-n">${riskCount}</div><div class="stat-l">Risk Matrix Entries</div></div>
      <div class="stat"><div class="stat-n">${selectedThreats}</div><div class="stat-l">Threats Selected for Requirements</div></div>
    </div>

    <div class="panel">
      <h2 class="pg-h2">Choosing a Methodology</h2>
      <p class="muted">Each threat modeling methodology has a different focus. Large threat models often combine several: STRIDE or attack trees for structural analysis, DREAD for quick relative scoring, PASTA for business-risk alignment, and LINDDUN whenever personal data is in scope.</p>
      <div class="tm-table-wrap">
        <table class="tm-table">
          <thead><tr><th>Methodology</th><th>Origin</th><th>Focus</th><th>Best For</th><th></th></tr></thead>
          <tbody>
            ${TM_METHODOLOGY_SUMMARIES.map((m) => `
              <tr>
                <td><strong>${tmEsc(m.name)}</strong></td>
                <td>${tmEsc(m.by)}</td>
                <td>${tmEsc(m.focus)}</td>
                <td>${tmEsc(m.best)}</td>
                <td><button type="button" class="btn sm ghost" data-goto="${m.tab}">Open</button></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>

    <div class="tm-grid tm-grid-2">
      <div class="card qa">
        <div class="qa-title">Recommended workflow</div>
        <div class="qa-desc">
          1. Build your data flow diagram inventory in <b>Data Flow Diagrams</b> to identify trust boundaries.<br>
          2. Walk the <b>STRIDE</b> checklist against each element crossing a trust boundary.<br>
          3. Browse the <b>Threat Library</b> and select threats relevant to your architecture.<br>
          4. Score priority threats with <b>DREAD</b> and/or map key attack paths with <b>Attack Trees</b>.<br>
          5. Generate <b>Security Requirements</b> from selected threats, plot them on the <b>Risk Matrix</b>, map to <b>Compliance</b> controls, then export the <b>Report</b>.
        </div>
      </div>
      <div class="card qa">
        <div class="qa-title">When to reach for PASTA or LINDDUN</div>
        <div class="qa-desc">
          Use <b>PASTA</b> when you need to justify security investment to business stakeholders with a clear likelihood x impact story tied to business objectives. Use <b>LINDDUN</b> whenever your system processes personal data and you need to reason about privacy threats distinct from security threats -- linking, identifying, and unwanted disclosure are not always caught by STRIDE alone.
        </div>
      </div>
    </div>
  `;

  container.querySelectorAll('[data-goto]').forEach((btn) => {
    btn.addEventListener('click', () => {
      tmState.activeTab = btn.getAttribute('data-goto');
      const tabBar = document.getElementById('tm-tab-bar');
      if (tabBar) {
        tabBar.querySelectorAll('[data-tab]').forEach((b) => b.classList.toggle('active', b.getAttribute('data-tab') === tmState.activeTab));
      }
      const content = document.getElementById('tm-tab-content');
      if (content) {
        content.innerHTML = '';
        switch (tmState.activeTab) {
          case 'stride': renderStrideSection(content); break;
          case 'dread': renderDreadSection(content); break;
          case 'attacktree': renderAttackTreeSection(content); break;
          case 'pasta': renderPastaSection(content); break;
          case 'linddun': renderLinddunSection(content); break;
          case 'dfd': renderDfdSection(content); break;
          default: renderOverviewSection(content);
        }
      }
    });
  });
}

/* ============================================================================
   SECTION 19: STRIDE INTERACTIVE SECTION
   ========================================================================== */

let tmStrideActiveCategory = 'spoofing';

function renderStrideSection(container) {
  const cat = STRIDE_CATEGORIES.find((c) => c.key === tmStrideActiveCategory) || STRIDE_CATEGORIES[0];
  const totalQ = STRIDE_CATEGORIES.reduce((s, c) => s + c.questions.length, 0);
  const doneQ = Object.values(tmState.stride.checked).filter(Boolean).length;
  const pct = totalQ ? Math.round((doneQ / totalQ) * 100) : 0;

  container.innerHTML = `
    <div class="panel">
      <div class="tm-flex-between">
        <div>
          <h2 class="pg-h2">STRIDE Threat Categories</h2>
          <p class="muted" style="max-width:760px;">STRIDE decomposes threats into six categories, each violating a specific security property. Walk through every question for every element that crosses a trust boundary in your system.</p>
        </div>
        <div style="min-width:180px;">
          <div class="tm-flex-between" style="margin-bottom:4px;"><span class="mono" style="font-size:12px;">${doneQ}/${totalQ} reviewed</span><span class="mono" style="font-size:12px;">${pct}%</span></div>
          <div class="tm-progress-bar"><div class="tm-progress-fill" style="width:${pct}%;"></div></div>
        </div>
      </div>
    </div>

    <div class="tm-section-nav" id="tm-stride-nav"></div>
    <div id="tm-stride-body"></div>
  `;

  const nav = container.querySelector('#tm-stride-nav');
  nav.innerHTML = STRIDE_CATEGORIES.map((c) => {
    const done = c.questions.filter((q) => tmState.stride.checked[q.id]).length;
    return `<button type="button" class="tm-pill${c.key === cat.key ? ' active' : ''}" data-cat="${c.key}">${c.letter} -- ${tmEsc(c.name)} (${done}/${c.questions.length})</button>`;
  }).join('');
  nav.querySelectorAll('[data-cat]').forEach((btn) => {
    btn.addEventListener('click', () => {
      tmStrideActiveCategory = btn.getAttribute('data-cat');
      renderStrideSection(container);
    });
  });

  const body = container.querySelector('#tm-stride-body');
  const catDone = cat.questions.filter((q) => tmState.stride.checked[q.id]).length;

  body.innerHTML = `
    <div class="tm-two-col">
      <div class="card">
        <div class="tm-flex-between">
          <h3 style="margin:0;">${cat.letter} -- ${tmEsc(cat.name)}</h3>
          <span class="tm-badge tm-badge-high">Violates: ${tmEsc(cat.violates)}</span>
        </div>
        <p class="muted" style="font-style:italic;">${tmEsc(cat.tagline)}</p>
        <p style="font-size:13.5px; line-height:1.6;">${tmEsc(cat.description)}</p>
        <h4 style="margin-bottom:6px;">Common Examples</h4>
        <ul class="tm-list-compact">${cat.examples.map((e) => `<li>${tmEsc(e)}</li>`).join('')}</ul>
        <h4 style="margin-bottom:6px;">Key Mitigations</h4>
        <ul class="tm-list-compact">${cat.mitigations.map((m) => `<li>${tmEsc(m)}</li>`).join('')}</ul>
      </div>
      <div class="card">
        <div class="tm-flex-between">
          <h3 style="margin:0;">Interactive Checklist</h3>
          <span class="mono" style="font-size:12px;">${catDone}/${cat.questions.length}</span>
        </div>
        <div>
          ${cat.questions.map((q) => `
            <label class="tm-checklist-item">
              <input type="checkbox" data-qid="${q.id}" ${tmState.stride.checked[q.id] ? 'checked' : ''} />
              <span>
                <span class="tm-checklist-q">${tmEsc(q.question)}</span>
                <span class="tm-checklist-g">${tmEsc(q.guidance)}</span>
              </span>
            </label>
          `).join('')}
        </div>
        <div class="tk-btns" style="margin-top:12px;">
          <button type="button" class="btn sm ghost" id="tm-stride-checkall">Mark all reviewed</button>
          <button type="button" class="btn sm ghost" id="tm-stride-clearall">Clear category</button>
        </div>
      </div>
    </div>
  `;

  body.querySelectorAll('[data-qid]').forEach((cb) => {
    cb.addEventListener('change', () => {
      tmState.stride.checked[cb.getAttribute('data-qid')] = cb.checked;
      renderStrideSection(container);
    });
  });
  const checkAllBtn = body.querySelector('#tm-stride-checkall');
  if (checkAllBtn) checkAllBtn.addEventListener('click', () => {
    cat.questions.forEach((q) => { tmState.stride.checked[q.id] = true; });
    renderStrideSection(container);
  });
  const clearAllBtn = body.querySelector('#tm-stride-clearall');
  if (clearAllBtn) clearAllBtn.addEventListener('click', () => {
    cat.questions.forEach((q) => { delete tmState.stride.checked[q.id]; });
    renderStrideSection(container);
  });
}

/* ============================================================================
   SECTION 20: DREAD CALCULATOR SECTION
   ========================================================================== */

let tmDreadDraftScores = { damage: 5, reproducibility: 5, exploitability: 5, affected_users: 5, discoverability: 5 };
let tmDreadDraftName = '';

function tmDreadLevelForScore(factor, score) {
  let closest = factor.levels[0];
  let bestDist = Infinity;
  for (const lvl of factor.levels) {
    const d = Math.abs(lvl.score - score);
    if (d < bestDist) { bestDist = d; closest = lvl; }
  }
  return closest;
}

function renderDreadSection(container) {
  const weightedNow = dreadWeightedScore(tmDreadDraftScores, tmState.dread.weights);
  const nowRating = dreadRatingLabel(weightedNow);

  container.innerHTML = `
    <div class="panel">
      <h2 class="pg-h2">DREAD Risk Scoring Calculator</h2>
      <p class="muted" style="max-width:760px;">DREAD scores a threat across five factors, each rated 0-10. The weighted average produces a single comparable risk score. DREAD is best used for quick, relative prioritization among threats already identified through STRIDE, PASTA, or an attack tree -- it does not identify threats itself.</p>
    </div>

    <div class="tm-two-col">
      <div class="card">
        <h3 style="margin-top:0;">New Threat Score</h3>
        <div class="tm-form-field">
          <label>Threat name</label>
          <input type="text" id="tm-dread-name" placeholder="e.g., SQL injection in search endpoint" value="${tmEsc(tmDreadDraftName)}" />
        </div>
        <div id="tm-dread-sliders"></div>
        <div class="tm-flex-between" style="margin-top:8px;">
          <div class="tm-score-ring" style="border-color:${nowRating.color};">
            <div class="tm-score-num" style="color:${nowRating.color};">${weightedNow.toFixed(1)}</div>
            <div class="tm-score-lbl">${tmEsc(nowRating.label)}</div>
          </div>
          <button type="button" class="btn" id="tm-dread-add">Add to List</button>
        </div>
      </div>

      <div class="card">
        <h3 style="margin-top:0;">Factor Weights</h3>
        <p class="muted" style="font-size:12.5px;">Adjust weights if some factors matter more to your organization (e.g., weight "Affected Users" higher for consumer-facing platforms).</p>
        <div id="tm-dread-weights"></div>
      </div>
    </div>

    <div class="panel">
      <div class="tm-flex-between">
        <h3 style="margin:0;">Scored Threats (${tmState.dread.entries.length})</h3>
        <div class="tk-btns">
          <button type="button" class="btn sm ghost" id="tm-dread-export">Export CSV</button>
          <button type="button" class="btn sm danger" id="tm-dread-clear">Clear All</button>
        </div>
      </div>
      <div id="tm-dread-list"></div>
    </div>
  `;

  // Sliders
  const slidersEl = container.querySelector('#tm-dread-sliders');
  slidersEl.innerHTML = DREAD_FACTORS.map((f) => {
    const val = tmDreadDraftScores[f.key];
    const lvl = tmDreadLevelForScore(f, val);
    return `
      <div class="tm-slider-row">
        <label><span>${tmEsc(f.name)}</span><span class="mono">${val}/10</span></label>
        <input type="range" min="0" max="10" step="1" value="${val}" data-factor="${f.key}" />
        <div class="tm-slider-level">${tmEsc(lvl.label)} -- ${tmEsc(lvl.desc)}</div>
      </div>
    `;
  }).join('');
  slidersEl.querySelectorAll('input[type=range]').forEach((inp) => {
    inp.addEventListener('input', () => {
      tmDreadDraftScores[inp.getAttribute('data-factor')] = Number(inp.value);
      renderDreadSection(container);
    });
  });

  // Weights
  const weightsEl = container.querySelector('#tm-dread-weights');
  weightsEl.innerHTML = DREAD_FACTORS.map((f) => {
    const w = tmState.dread.weights[f.key];
    return `
      <div class="tm-slider-row">
        <label><span>${tmEsc(f.name)} weight</span><span class="mono">${w.toFixed(1)}x</span></label>
        <input type="range" min="0" max="3" step="0.1" value="${w}" data-weight="${f.key}" />
      </div>
    `;
  }).join('');
  weightsEl.querySelectorAll('input[type=range]').forEach((inp) => {
    inp.addEventListener('input', () => {
      tmState.dread.weights[inp.getAttribute('data-weight')] = Number(inp.value);
      renderDreadSection(container);
    });
  });

  // Name input
  const nameInput = container.querySelector('#tm-dread-name');
  nameInput.addEventListener('input', () => { tmDreadDraftName = nameInput.value; });

  // Add button
  container.querySelector('#tm-dread-add').addEventListener('click', () => {
    const name = tmDreadDraftName.trim() || 'Untitled threat';
    tmState.dread.entries.push({ id: tmUid('dread'), name, scores: tmClone(tmDreadDraftScores) });
    tmDreadDraftName = '';
    tmDreadDraftScores = { damage: 5, reproducibility: 5, exploitability: 5, affected_users: 5, discoverability: 5 };
    renderDreadSection(container);
  });

  // List
  const listEl = container.querySelector('#tm-dread-list');
  if (tmState.dread.entries.length === 0) {
    listEl.innerHTML = '<div class="tm-empty">No threats scored yet. Use the calculator above to add one.</div>';
  } else {
    const sorted = tmState.dread.entries
      .map((e) => ({ ...e, weighted: dreadWeightedScore(e.scores, tmState.dread.weights) }))
      .sort((a, b) => b.weighted - a.weighted);
    listEl.innerHTML = `
      <div class="tm-table-wrap">
        <table class="tm-table">
          <thead><tr><th>Threat</th><th>D</th><th>R</th><th>E</th><th>A</th><th>D</th><th>Score</th><th>Rating</th><th></th></tr></thead>
          <tbody>
            ${sorted.map((e) => {
              const r = dreadRatingLabel(e.weighted);
              return `
                <tr>
                  <td>${tmEsc(e.name)}</td>
                  <td class="mono">${e.scores.damage}</td>
                  <td class="mono">${e.scores.reproducibility}</td>
                  <td class="mono">${e.scores.exploitability}</td>
                  <td class="mono">${e.scores.affected_users}</td>
                  <td class="mono">${e.scores.discoverability}</td>
                  <td class="mono" style="font-weight:700;">${e.weighted.toFixed(1)}</td>
                  <td><span class="tm-badge tm-badge-${r.label.toLowerCase()}">${tmEsc(r.label)}</span></td>
                  <td><button type="button" class="btn sm ghost" data-remove="${e.id}">Remove</button></td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
    listEl.querySelectorAll('[data-remove]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-remove');
        tmState.dread.entries = tmState.dread.entries.filter((e) => e.id !== id);
        renderDreadSection(container);
      });
    });
  }

  container.querySelector('#tm-dread-clear').addEventListener('click', () => {
    if (tmState.dread.entries.length === 0) return;
    tmState.dread.entries = [];
    renderDreadSection(container);
  });

  container.querySelector('#tm-dread-export').addEventListener('click', () => {
    const header = ['Threat', 'Damage', 'Reproducibility', 'Exploitability', 'AffectedUsers', 'Discoverability', 'WeightedScore', 'Rating'];
    const rows = tmState.dread.entries.map((e) => {
      const w = dreadWeightedScore(e.scores, tmState.dread.weights);
      const r = dreadRatingLabel(w);
      return [e.name, e.scores.damage, e.scores.reproducibility, e.scores.exploitability, e.scores.affected_users, e.scores.discoverability, w.toFixed(2), r.label]
        .map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',');
    });
    tmDownload('dread-scores.csv', [header.join(','), ...rows].join('\n'));
  });
}

/* ============================================================================
   SECTION 21: ATTACK TREE BUILDER
   ========================================================================== */

function tmAttackTreeChildren(nodeId) {
  return tmState.attackTree.nodes.filter((n) => n.parentId === nodeId);
}

function tmAttackTreeComputeProb(nodeId) {
  const node = tmState.attackTree.nodes.find((n) => n.id === nodeId);
  if (!node) return 0;
  const children = tmAttackTreeChildren(nodeId);
  if (children.length === 0) {
    return tmClamp(Number(node.probability) || 0, 0, 1);
  }
  const childProbs = children.map((c) => tmAttackTreeComputeProb(c.id));
  if (node.gate === 'AND') {
    return childProbs.reduce((acc, p) => acc * p, 1);
  }
  // OR gate: probability that at least one path succeeds (assumes independence)
  const failAll = childProbs.reduce((acc, p) => acc * (1 - p), 1);
  return 1 - failAll;
}

function tmAttackTreeRemoveSubtree(nodeId) {
  const toRemove = new Set([nodeId]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const n of tmState.attackTree.nodes) {
      if (toRemove.has(n.parentId) && !toRemove.has(n.id)) {
        toRemove.add(n.id);
        changed = true;
      }
    }
  }
  tmState.attackTree.nodes = tmState.attackTree.nodes.filter((n) => !toRemove.has(n.id));
}

function tmAttackTreeNodeHtml(nodeId, depth) {
  const node = tmState.attackTree.nodes.find((n) => n.id === nodeId);
  if (!node) return '';
  const children = tmAttackTreeChildren(nodeId);
  const isLeaf = children.length === 0;
  const prob = tmAttackTreeComputeProb(nodeId);
  const pct = Math.round(prob * 100);
  const color = pct >= 70 ? '#ff2e63' : pct >= 40 ? '#ffbd2e' : '#27c93f';

  let html = `
    <div class="tm-tree-node" data-node="${node.id}">
      <div class="tm-tree-row">
        <input type="text" data-edit-label="${node.id}" value="${tmEsc(node.label)}" placeholder="Attack step description" />
        ${!isLeaf ? `
          <select data-edit-gate="${node.id}">
            <option value="OR" ${node.gate === 'OR' ? 'selected' : ''}>OR (any child succeeds)</option>
            <option value="AND" ${node.gate === 'AND' ? 'selected' : ''}>AND (all children required)</option>
          </select>
        ` : `
          <label style="font-size:12px; display:flex; align-items:center; gap:4px;">
            P(success):
            <input type="number" data-edit-prob="${node.id}" min="0" max="1" step="0.05" value="${node.probability}" />
          </label>
        `}
        <span class="tm-badge" style="border-color:${color}; color:${color};">${pct}%</span>
        <button type="button" class="btn sm ghost" data-add-child="${node.id}">+ Child</button>
        ${node.parentId !== null ? `<button type="button" class="btn sm danger" data-remove-node="${node.id}">Remove</button>` : ''}
      </div>
    </div>
  `;
  if (children.length > 0) {
    html += `<div class="tm-tree-children">${children.map((c) => tmAttackTreeNodeHtml(c.id, depth + 1)).join('')}</div>`;
  }
  return html;
}

function renderAttackTreeSection(container) {
  const rootProb = tmAttackTreeComputeProb('root');
  const pct = Math.round(rootProb * 100);

  container.innerHTML = `
    <div class="panel">
      <h2 class="pg-h2">Attack Tree Builder</h2>
      <p class="muted" style="max-width:760px;">Attack trees model the specific paths an attacker could take to achieve one high-value goal. The root node is the attacker's ultimate objective; each level down decomposes that objective into concrete sub-steps. Leaf nodes carry an estimated probability of success; branch nodes combine their children with an <b>OR</b> gate (any single child succeeding is enough) or an <b>AND</b> gate (all children are required).</p>
    </div>

    <div class="tm-two-col">
      <div class="card">
        <div class="tm-form-field">
          <label>Attack goal (root node)</label>
          <input type="text" id="tm-tree-goal" value="${tmEsc(tmState.attackTree.goal)}" />
        </div>
        <div id="tm-tree-body"></div>
      </div>
      <div class="card" style="text-align:center;">
        <h3 style="margin-top:0;">Overall Attack Probability</h3>
        <div class="tm-score-ring" style="border-color:${pct >= 70 ? '#ff2e63' : pct >= 40 ? '#ffbd2e' : '#27c93f'}; width:150px; height:150px;">
          <div class="tm-score-num" style="font-size:38px;">${pct}%</div>
          <div class="tm-score-lbl">Likelihood</div>
        </div>
        <p class="muted" style="font-size:12.5px; margin-top:14px;">This estimate assumes each leaf-node probability is independent. Use it for relative comparison between attack trees, not as an absolute statistical guarantee.</p>
        <div class="tk-btns" style="justify-content:center;">
          <button type="button" class="btn sm ghost" id="tm-tree-reset">Reset Tree</button>
          <button type="button" class="btn sm ghost" id="tm-tree-export">Export as Text</button>
        </div>
      </div>
    </div>
  `;

  const goalInput = container.querySelector('#tm-tree-goal');
  goalInput.addEventListener('input', () => {
    tmState.attackTree.goal = goalInput.value;
    const root = tmState.attackTree.nodes.find((n) => n.id === 'root');
    if (root) root.label = goalInput.value;
  });

  const body = container.querySelector('#tm-tree-body');
  body.innerHTML = tmAttackTreeNodeHtml('root', 0);

  body.querySelectorAll('[data-edit-label]').forEach((inp) => {
    inp.addEventListener('input', () => {
      const id = inp.getAttribute('data-edit-label');
      const node = tmState.attackTree.nodes.find((n) => n.id === id);
      if (node) {
        node.label = inp.value;
        if (id === 'root') {
          tmState.attackTree.goal = inp.value;
          const goalEl = container.querySelector('#tm-tree-goal');
          if (goalEl) goalEl.value = inp.value;
        }
      }
    });
  });
  body.querySelectorAll('[data-edit-gate]').forEach((sel) => {
    sel.addEventListener('change', () => {
      const id = sel.getAttribute('data-edit-gate');
      const node = tmState.attackTree.nodes.find((n) => n.id === id);
      if (node) node.gate = sel.value;
      renderAttackTreeSection(container);
    });
  });
  body.querySelectorAll('[data-edit-prob]').forEach((inp) => {
    inp.addEventListener('input', () => {
      const id = inp.getAttribute('data-edit-prob');
      const node = tmState.attackTree.nodes.find((n) => n.id === id);
      if (node) node.probability = tmClamp(Number(inp.value) || 0, 0, 1);
      renderAttackTreeSection(container);
    });
  });
  body.querySelectorAll('[data-add-child]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const parentId = btn.getAttribute('data-add-child');
      const parent = tmState.attackTree.nodes.find((n) => n.id === parentId);
      if (parent && tmAttackTreeChildren(parentId).length === 0) parent.gate = parent.gate || 'OR';
      tmState.attackTree.nodes.push({ id: tmUid('node'), parentId, label: 'New attack step', probability: 0.3, gate: 'OR' });
      renderAttackTreeSection(container);
    });
  });
  body.querySelectorAll('[data-remove-node]').forEach((btn) => {
    btn.addEventListener('click', () => {
      tmAttackTreeRemoveSubtree(btn.getAttribute('data-remove-node'));
      renderAttackTreeSection(container);
    });
  });

  container.querySelector('#tm-tree-reset').addEventListener('click', () => {
    tmState.attackTree.nodes = [{ id: 'root', parentId: null, label: tmState.attackTree.goal, probability: 0.5, gate: 'OR' }];
    renderAttackTreeSection(container);
  });

  container.querySelector('#tm-tree-export').addEventListener('click', () => {
    function walk(id, depth) {
      const node = tmState.attackTree.nodes.find((n) => n.id === id);
      const children = tmAttackTreeChildren(id);
      const prob = Math.round(tmAttackTreeComputeProb(id) * 100);
      let out = `${'  '.repeat(depth)}- ${node.label} [${prob}%]${children.length ? ` (${node.gate})` : ''}\n`;
      for (const c of children) out += walk(c.id, depth + 1);
      return out;
    }
    tmDownload('attack-tree.txt', `Attack Tree: ${tmState.attackTree.goal}\n\n${walk('root', 0)}`);
  });
}

/* ============================================================================
   SECTION 22: PASTA REFERENCE SECTION
   ========================================================================== */

function renderPastaSection(container) {
  container.innerHTML = `
    <div class="panel">
      <h2 class="pg-h2">PASTA -- Process for Attack Simulation and Threat Analysis</h2>
      <p class="muted" style="max-width:780px;">PASTA is a seven-stage, risk-centric threat modeling methodology developed by VerSprite. Unlike STRIDE, which starts from technical decomposition, PASTA explicitly begins and ends with business objectives -- every technical finding is ultimately translated into business risk and a costed treatment recommendation. PASTA is well suited to enterprise threat modeling engagements where security investment must be justified to non-technical stakeholders.</p>
    </div>
    <div id="tm-pasta-stages"></div>
  `;
  const stagesEl = container.querySelector('#tm-pasta-stages');
  stagesEl.innerHTML = PASTA_STAGES.map((s) => `
    <div class="tm-stage-card">
      <div class="tm-flex-between">
        <h3 style="margin:0;"><span class="tm-stage-num">${s.stage}</span>${tmEsc(s.name)} <span class="muted" style="font-weight:400; font-size:13px;">(${tmEsc(s.abbr)})</span></h3>
      </div>
      <p style="font-size:13px; font-weight:600; opacity:.85; margin:8px 0;">${tmEsc(s.objective)}</p>
      <div class="tm-two-col">
        <div>
          ${s.narrative.split('\n\n').map((p) => `<p style="font-size:13px; line-height:1.65;">${tmEsc(p)}</p>`).join('')}
        </div>
        <div>
          <h4 style="margin-bottom:6px;">Key Activities</h4>
          <ul class="tm-list-compact">${s.activities.map((a) => `<li>${tmEsc(a)}</li>`).join('')}</ul>
          <h4 style="margin-bottom:6px; margin-top:12px;">Deliverables</h4>
          <ul class="tm-list-compact">${s.deliverables.map((d) => `<li>${tmEsc(d)}</li>`).join('')}</ul>
        </div>
      </div>
    </div>
  `).join('');
}

/* ============================================================================
   SECTION 23: LINDDUN PRIVACY THREAT MODELING SECTION
   ========================================================================== */

function renderLinddunSection(container) {
  const doneCount = LINDDUN_CATEGORIES.filter((c) => tmState.linddun.checked[c.key]).length;

  container.innerHTML = `
    <div class="panel">
      <div class="tm-flex-between">
        <div>
          <h2 class="pg-h2">LINDDUN -- Privacy Threat Modeling</h2>
          <p class="muted" style="max-width:780px;">LINDDUN is a privacy-focused threat modeling methodology developed at KU Leuven. It complements STRIDE by covering threats that STRIDE does not directly address -- linking, identifying, and other privacy-specific risks that can exist even in a system with no traditional security vulnerabilities at all. Use LINDDUN whenever your system collects, processes, or stores personal data.</p>
        </div>
        <span class="mono" style="font-size:12px;">${doneCount}/${LINDDUN_CATEGORIES.length} categories assessed</span>
      </div>
    </div>
    <div class="tm-grid tm-grid-2" id="tm-linddun-grid"></div>
  `;

  const grid = container.querySelector('#tm-linddun-grid');
  grid.innerHTML = LINDDUN_CATEGORIES.map((c) => {
    const checked = !!tmState.linddun.checked[c.key];
    return `
      <div class="card">
        <div class="tm-flex-between">
          <h3 style="margin:0;">${c.letter} -- ${tmEsc(c.name)}</h3>
          <label style="display:flex; align-items:center; gap:6px; font-size:12px;">
            <input type="checkbox" data-linddun="${c.key}" ${checked ? 'checked' : ''} />
            Assessed
          </label>
        </div>
        <p class="muted" style="font-style:italic; font-size:13px;">${tmEsc(c.tagline)}</p>
        <p style="font-size:13px; line-height:1.6;">${tmEsc(c.description)}</p>
        <h4 style="margin-bottom:6px;">Examples</h4>
        <ul class="tm-list-compact">${c.examples.map((e) => `<li>${tmEsc(e)}</li>`).join('')}</ul>
        <h4 style="margin-bottom:6px; margin-top:10px;">Mitigations</h4>
        <ul class="tm-list-compact">${c.mitigations.map((m) => `<li>${tmEsc(m)}</li>`).join('')}</ul>
      </div>
    `;
  }).join('');

  grid.querySelectorAll('[data-linddun]').forEach((cb) => {
    cb.addEventListener('change', () => {
      tmState.linddun.checked[cb.getAttribute('data-linddun')] = cb.checked;
      renderLinddunSection(container);
    });
  });
}

/* ============================================================================
   SECTION 24: DATA FLOW DIAGRAM REFERENCE SECTION
   ========================================================================== */

function renderDfdSection(container) {
  container.innerHTML = `
    <div class="panel">
      <h2 class="pg-h2">Data Flow Diagram (DFD) Reference</h2>
      <p class="muted" style="max-width:780px;">Data flow diagrams are the structural backbone shared by most threat modeling methodologies. Before threats can be systematically enumerated, the system must be decomposed into external entities, processes, data stores, data flows, and the trust boundaries between them. Every element type below carries a different subset of STRIDE relevance.</p>
    </div>
    <div class="tm-grid tm-grid-2" id="tm-dfd-elements"></div>
    <div class="panel">
      <h3 style="margin-top:0;">Common Trust Boundary Patterns</h3>
      <p class="muted" style="font-size:13px;">Trust boundaries are the single most important construct in a data flow diagram -- the overwhelming majority of real-world threats occur at the point where an assumption of trust must be explicitly re-verified. Below are the trust boundary patterns that recur across most system architectures.</p>
      <div class="tm-table-wrap">
        <table class="tm-table">
          <thead><tr><th>Boundary Pattern</th><th>Description</th></tr></thead>
          <tbody>
            ${DFD_TRUST_BOUNDARY_PATTERNS.map((p) => `<tr><td style="white-space:nowrap; font-weight:600;">${tmEsc(p.name)}</td><td>${tmEsc(p.description)}</td></tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>
    <div class="panel">
      <h3 style="margin-top:0;">Building Your DFD -- Practical Checklist</h3>
      <ul class="tm-list-compact" style="font-size:13.5px;">
        <li>Start with a Level-0 (context) diagram showing the system as a single process bounded by its external entities.</li>
        <li>Decompose into a Level-1 diagram showing major internal processes, data stores, and flows between them.</li>
        <li>Draw a dashed trust-boundary line everywhere data crosses a privilege, network, or organizational boundary.</li>
        <li>Label every data flow with what data it carries and whether it is encrypted/authenticated.</li>
        <li>Validate the diagram with the engineers who actually built the system -- diagrams drift out of date quickly.</li>
        <li>Use the completed diagram as the map for walking the STRIDE checklist against each element and boundary.</li>
      </ul>
    </div>
  `;

  const elGrid = container.querySelector('#tm-dfd-elements');
  elGrid.innerHTML = DFD_ELEMENTS.map((el) => `
    <div class="card">
      <div class="tm-flex-between">
        <h3 style="margin:0;">${tmEsc(el.name)}</h3>
        <span class="mono" style="font-size:16px; opacity:.6;">${tmEsc(el.symbol)}</span>
      </div>
      <div class="muted" style="font-size:12px; margin-bottom:6px;">Shape: ${tmEsc(el.shape)}</div>
      <p style="font-size:13px; line-height:1.6;">${tmEsc(el.description)}</p>
      <div style="margin:8px 0;"><b style="font-size:12px; opacity:.75;">STRIDE relevance:</b> ${el.strideRelevance.map((s) => `<span class="tm-badge tm-badge-info" style="margin:2px 3px 0 0;">${tmEsc(s)}</span>`).join('')}</div>
      <div style="font-size:12.5px;"><b style="opacity:.75;">Examples:</b> ${el.examples.map(tmEsc).join(', ')}</div>
    </div>
  `).join('');
}

/* ============================================================================
   SECTION 25: THREAT LIBRARY BROWSER SECTION
   ========================================================================== */

const TM_STRIDE_LABELS = {
  spoofing: 'Spoofing',
  tampering: 'Tampering',
  repudiation: 'Repudiation',
  information_disclosure: 'Information Disclosure',
  denial_of_service: 'Denial of Service',
  elevation_of_privilege: 'Elevation of Privilege',
};

function tmAllThreatsFlat() {
  const out = [];
  for (const cat of Object.keys(THREAT_LIBRARY)) {
    for (const t of THREAT_LIBRARY[cat]) {
      out.push({ ...t, category: cat });
    }
  }
  return out;
}

function renderThreatLibrarySection(container) {
  const all = tmAllThreatsFlat();
  const filtered = all.filter((t) => {
    if (tmState.threatLibrary.filterCategory !== 'all' && t.category !== tmState.threatLibrary.filterCategory) return false;
    if (tmState.threatLibrary.filterSeverity !== 'all' && t.severity !== tmState.threatLibrary.filterSeverity) return false;
    if (tmState.threatLibrary.search) {
      const q = tmState.threatLibrary.search.toLowerCase();
      const hay = `${t.title} ${t.description} ${t.id}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  const selectedCount = Object.values(tmState.threatLibrary.selected).filter(Boolean).length;

  container.innerHTML = `
    <div class="panel">
      <div class="tm-flex-between">
        <div>
          <h2 class="pg-h2">Threat Library</h2>
          <p class="muted" style="max-width:700px;">${all.length} real-world threats across all six STRIDE categories, each with a CWE reference, concrete example, and mitigation. Select threats relevant to your system to seed the Security Requirements generator.</p>
        </div>
        <div class="stat"><div class="stat-n">${selectedCount}</div><div class="stat-l">Selected</div></div>
      </div>
      <div class="tm-grid tm-grid-3" style="margin-top:14px;">
        <div class="tm-form-field" style="margin-bottom:0;">
          <label>Search</label>
          <input type="text" id="tm-lib-search" placeholder="Search title, description, ID..." value="${tmEsc(tmState.threatLibrary.search)}" />
        </div>
        <div class="tm-form-field" style="margin-bottom:0;">
          <label>Category</label>
          <select id="tm-lib-cat">
            <option value="all" ${tmState.threatLibrary.filterCategory === 'all' ? 'selected' : ''}>All Categories</option>
            ${Object.keys(TM_STRIDE_LABELS).map((k) => `<option value="${k}" ${tmState.threatLibrary.filterCategory === k ? 'selected' : ''}>${TM_STRIDE_LABELS[k]}</option>`).join('')}
          </select>
        </div>
        <div class="tm-form-field" style="margin-bottom:0;">
          <label>Severity</label>
          <select id="tm-lib-sev">
            <option value="all" ${tmState.threatLibrary.filterSeverity === 'all' ? 'selected' : ''}>All Severities</option>
            <option value="Critical" ${tmState.threatLibrary.filterSeverity === 'Critical' ? 'selected' : ''}>Critical</option>
            <option value="High" ${tmState.threatLibrary.filterSeverity === 'High' ? 'selected' : ''}>High</option>
            <option value="Medium" ${tmState.threatLibrary.filterSeverity === 'Medium' ? 'selected' : ''}>Medium</option>
            <option value="Low" ${tmState.threatLibrary.filterSeverity === 'Low' ? 'selected' : ''}>Low</option>
          </select>
        </div>
      </div>
    </div>

    <div class="tm-flex-between" style="margin-bottom:4px;">
      <span class="muted" style="font-size:12.5px;">Showing ${filtered.length} of ${all.length} threats</span>
      <button type="button" class="btn sm ghost" id="tm-lib-export">Export Selected (CSV)</button>
    </div>
    <div class="tm-grid tm-grid-2" id="tm-lib-results"></div>
  `;

  const searchInput = container.querySelector('#tm-lib-search');
  searchInput.addEventListener('input', () => {
    tmState.threatLibrary.search = searchInput.value;
    renderThreatLibrarySection(container);
  });
  container.querySelector('#tm-lib-cat').addEventListener('change', (e) => {
    tmState.threatLibrary.filterCategory = e.target.value;
    renderThreatLibrarySection(container);
  });
  container.querySelector('#tm-lib-sev').addEventListener('change', (e) => {
    tmState.threatLibrary.filterSeverity = e.target.value;
    renderThreatLibrarySection(container);
  });

  const results = container.querySelector('#tm-lib-results');
  if (filtered.length === 0) {
    results.innerHTML = '<div class="tm-empty">No threats match the current filters.</div>';
  } else {
    results.innerHTML = filtered.map((t) => {
      const selected = !!tmState.threatLibrary.selected[t.id];
      return `
        <div class="tm-threat-card">
          <div class="tm-threat-meta">
            <span class="mono" style="font-size:11px; opacity:.6;">${tmEsc(t.id)}</span>
            <span class="tm-badge tm-badge-${t.severity.toLowerCase()}">${tmEsc(t.severity)}</span>
            <span class="tm-badge tm-badge-info">${tmEsc(TM_STRIDE_LABELS[t.category])}</span>
            <span class="mono" style="font-size:11px; opacity:.5;">${tmEsc(t.cwe)}</span>
          </div>
          <h4>${tmEsc(t.title)}</h4>
          <div class="tm-threat-field">${tmEsc(t.description)}</div>
          <div class="tm-threat-field"><b>Example:</b>${tmEsc(t.example)}</div>
          <div class="tm-threat-field"><b>Mitigation:</b>${tmEsc(t.mitigation)}</div>
          <label style="display:flex; align-items:center; gap:6px; font-size:12px; margin-top:8px;">
            <input type="checkbox" data-select-threat="${t.id}" ${selected ? 'checked' : ''} />
            Select for security requirements
          </label>
        </div>
      `;
    }).join('');
    results.querySelectorAll('[data-select-threat]').forEach((cb) => {
      cb.addEventListener('change', () => {
        tmState.threatLibrary.selected[cb.getAttribute('data-select-threat')] = cb.checked;
        renderThreatLibrarySection(container);
      });
    });
  }

  container.querySelector('#tm-lib-export').addEventListener('click', () => {
    const selectedThreats = all.filter((t) => tmState.threatLibrary.selected[t.id]);
    if (selectedThreats.length === 0) { tmDownload('threat-library-selection.csv', 'No threats selected.'); return; }
    const header = ['ID', 'Category', 'Title', 'Severity', 'CWE', 'Description', 'Example', 'Mitigation'];
    const rows = selectedThreats.map((t) => [t.id, TM_STRIDE_LABELS[t.category], t.title, t.severity, t.cwe, t.description, t.example, t.mitigation]
      .map((v) => `"${String(v).replace(/"/g, '""')}"`).join(','));
    tmDownload('threat-library-selection.csv', [header.join(','), ...rows].join('\n'));
  });
}

/* ============================================================================
   SECTION 26: ASSET INVENTORY BUILDER SECTION
   ========================================================================== */

function tmNewAsset() {
  const asset = { id: tmUid('asset') };
  for (const f of ASSET_INVENTORY_FIELDS) asset[f.key] = '';
  asset.sensitivity = ASSET_SENSITIVITY_LEVELS[0];
  asset.confidentiality = ASSET_CIA_LEVELS[0];
  asset.integrity = ASSET_CIA_LEVELS[0];
  asset.availability = ASSET_CIA_LEVELS[0];
  asset.type = ASSET_TYPES[0];
  return asset;
}

function renderAssetInventorySection(container) {
  container.innerHTML = `
    <div class="panel">
      <div class="tm-flex-between">
        <div>
          <h2 class="pg-h2">Asset Inventory</h2>
          <p class="muted" style="max-width:700px;">Every threat model needs a concrete list of what is being protected. Build an asset inventory capturing ownership, sensitivity classification, and CIA (confidentiality, integrity, availability) impact requirements for each asset -- this feeds directly into the risk matrix and report.</p>
        </div>
        <div class="tk-btns">
          <button type="button" class="btn sm" id="tm-asset-add">+ Add Asset</button>
          <button type="button" class="btn sm ghost" id="tm-asset-export">Export CSV</button>
        </div>
      </div>
    </div>
    <div id="tm-asset-list"></div>
  `;

  container.querySelector('#tm-asset-add').addEventListener('click', () => {
    tmState.assets.push(tmNewAsset());
    renderAssetInventorySection(container);
  });

  container.querySelector('#tm-asset-export').addEventListener('click', () => {
    if (tmState.assets.length === 0) { tmDownload('asset-inventory.csv', 'No assets recorded.'); return; }
    const header = ASSET_INVENTORY_FIELDS.map((f) => f.label);
    const rows = tmState.assets.map((a) => ASSET_INVENTORY_FIELDS.map((f) => `"${String(a[f.key] || '').replace(/"/g, '""')}"`).join(','));
    tmDownload('asset-inventory.csv', [header.join(','), ...rows].join('\n'));
  });

  const list = container.querySelector('#tm-asset-list');
  if (tmState.assets.length === 0) {
    list.innerHTML = `
      <div class="card tm-empty">
        No assets recorded yet. Click "Add Asset" to start building your inventory.
        <div style="margin-top:10px;">
          <button type="button" class="btn sm ghost" id="tm-asset-seed">Seed example assets</button>
        </div>
      </div>
    `;
    const seedBtn = list.querySelector('#tm-asset-seed');
    if (seedBtn) seedBtn.addEventListener('click', () => {
      const examples = [
        { name: 'Customer Database', type: 'Database', owner: 'Platform Team', description: 'Primary PostgreSQL database storing customer accounts and PII.', sensitivity: 'Restricted', confidentiality: 'High', integrity: 'High', availability: 'High' },
        { name: 'Authentication Service', type: 'API / Service', owner: 'Identity Team', description: 'Handles login, MFA, and session issuance for all products.', sensitivity: 'Confidential', confidentiality: 'High', integrity: 'High', availability: 'High' },
        { name: 'Marketing Website', type: 'Application', owner: 'Web Team', description: 'Public marketing site with no authenticated functionality.', sensitivity: 'Public', confidentiality: 'Low', integrity: 'Medium', availability: 'Medium' },
        { name: 'Payment Processing Integration', type: 'Third-Party Integration', owner: 'Payments Team', description: 'Server-to-server integration with the payment gateway.', sensitivity: 'Restricted', confidentiality: 'High', integrity: 'High', availability: 'High' },
      ];
      for (const ex of examples) {
        const a = tmNewAsset();
        Object.assign(a, ex);
        tmState.assets.push(a);
      }
      renderAssetInventorySection(container);
    });
  } else {
    list.innerHTML = tmState.assets.map((a, idx) => `
      <div class="card" data-asset-card="${a.id}">
        <div class="tm-flex-between">
          <h3 style="margin:0;">Asset #${idx + 1}${a.name ? `: ${tmEsc(a.name)}` : ''}</h3>
          <button type="button" class="btn sm danger" data-remove-asset="${a.id}">Remove</button>
        </div>
        <div class="tm-grid tm-grid-3">
          ${ASSET_INVENTORY_FIELDS.map((f) => `
            <div class="tm-form-field">
              <label>${tmEsc(f.label)}${f.required ? ' *' : ''}</label>
              ${f.type === 'select'
                ? `<select data-asset-field="${a.id}:${f.key}">${f.options.map((o) => `<option value="${tmEsc(o)}" ${a[f.key] === o ? 'selected' : ''}>${tmEsc(o)}</option>`).join('')}</select>`
                : f.type === 'textarea'
                  ? `<textarea data-asset-field="${a.id}:${f.key}" placeholder="${tmEsc(f.help)}">${tmEsc(a[f.key])}</textarea>`
                  : `<input type="text" data-asset-field="${a.id}:${f.key}" value="${tmEsc(a[f.key])}" placeholder="${tmEsc(f.help)}" />`}
            </div>
          `).join('')}
        </div>
      </div>
    `).join('');

    list.querySelectorAll('[data-asset-field]').forEach((el) => {
      el.addEventListener('input', () => {
        const [id, key] = el.getAttribute('data-asset-field').split(':');
        const asset = tmState.assets.find((a) => a.id === id);
        if (asset) asset[key] = el.value;
        if (key === 'name') {
          const card = list.querySelector(`[data-asset-card="${id}"] h3`);
          if (card) {
            const idx = tmState.assets.findIndex((a) => a.id === id);
            card.textContent = `Asset #${idx + 1}${el.value ? `: ${el.value}` : ''}`;
          }
        }
      });
      if (el.tagName === 'SELECT') {
        el.addEventListener('change', () => {
          const [id, key] = el.getAttribute('data-asset-field').split(':');
          const asset = tmState.assets.find((a) => a.id === id);
          if (asset) asset[key] = el.value;
        });
      }
    });
    list.querySelectorAll('[data-remove-asset]').forEach((btn) => {
      btn.addEventListener('click', () => {
        tmState.assets = tmState.assets.filter((a) => a.id !== btn.getAttribute('data-remove-asset'));
        renderAssetInventorySection(container);
      });
    });
  }
}

/* ============================================================================
   SECTION 27: RISK MATRIX GENERATOR SECTION
   ========================================================================== */

let tmRiskDraft = { name: '', likelihood: 3, impact: 3, notes: '' };

function renderRiskMatrixSection(container) {
  const lScale = tmState.riskMatrix.likelihood;
  const iScale = tmState.riskMatrix.impact;

  container.innerHTML = `
    <div class="panel">
      <h2 class="pg-h2">Risk Matrix Generator</h2>
      <p class="muted" style="max-width:760px;">Plot identified risks on a likelihood x impact grid to visualize and prioritize your risk register. The default 5x5 scale is customizable -- edit the labels and descriptions below to match your organization's existing risk taxonomy.</p>
    </div>

    <div class="tm-two-col">
      <div class="card">
        <h3 style="margin-top:0;">Add a Risk</h3>
        <div class="tm-form-field">
          <label>Risk name</label>
          <input type="text" id="tm-risk-name" value="${tmEsc(tmRiskDraft.name)}" placeholder="e.g., Unauthenticated admin API" />
        </div>
        <div class="tm-grid tm-grid-2">
          <div class="tm-form-field">
            <label>Likelihood</label>
            <select id="tm-risk-likelihood">${lScale.map((l) => `<option value="${l.level}" ${tmRiskDraft.likelihood === l.level ? 'selected' : ''}>${l.level} -- ${tmEsc(l.label)}</option>`).join('')}</select>
          </div>
          <div class="tm-form-field">
            <label>Impact</label>
            <select id="tm-risk-impact">${iScale.map((i) => `<option value="${i.level}" ${tmRiskDraft.impact === i.level ? 'selected' : ''}>${i.level} -- ${tmEsc(i.label)}</option>`).join('')}</select>
          </div>
        </div>
        <div class="tm-form-field">
          <label>Notes</label>
          <textarea id="tm-risk-notes" placeholder="Optional context">${tmEsc(tmRiskDraft.notes)}</textarea>
        </div>
        <button type="button" class="btn" id="tm-risk-add">Add to Matrix</button>
      </div>
      <div class="card">
        <h3 style="margin-top:0;">Customize Scales</h3>
        <p class="muted" style="font-size:12.5px;">Edit level labels to align with your organization's terminology.</p>
        <div class="tm-two-col">
          <div>
            <h4 style="margin-bottom:6px;">Likelihood</h4>
            ${lScale.map((l) => `<div class="tm-form-field"><label>Level ${l.level}</label><input type="text" data-scale="likelihood:${l.level}" value="${tmEsc(l.label)}" /></div>`).join('')}
          </div>
          <div>
            <h4 style="margin-bottom:6px;">Impact</h4>
            ${iScale.map((i) => `<div class="tm-form-field"><label>Level ${i.level}</label><input type="text" data-scale="impact:${i.level}" value="${tmEsc(i.label)}" /></div>`).join('')}
          </div>
        </div>
      </div>
    </div>

    <div class="panel">
      <h3 style="margin-top:0;">Risk Matrix Grid</h3>
      <div class="tm-table-wrap" id="tm-risk-grid"></div>
    </div>

    <div class="panel">
      <div class="tm-flex-between">
        <h3 style="margin:0;">Risk Register (${tmState.riskMatrix.risks.length})</h3>
        <button type="button" class="btn sm ghost" id="tm-risk-export">Export CSV</button>
      </div>
      <div id="tm-risk-register"></div>
    </div>
  `;

  container.querySelector('#tm-risk-name').addEventListener('input', (e) => { tmRiskDraft.name = e.target.value; });
  container.querySelector('#tm-risk-likelihood').addEventListener('change', (e) => { tmRiskDraft.likelihood = Number(e.target.value); });
  container.querySelector('#tm-risk-impact').addEventListener('change', (e) => { tmRiskDraft.impact = Number(e.target.value); });
  container.querySelector('#tm-risk-notes').addEventListener('input', (e) => { tmRiskDraft.notes = e.target.value; });
  container.querySelector('#tm-risk-add').addEventListener('click', () => {
    const name = tmRiskDraft.name.trim() || 'Untitled risk';
    tmState.riskMatrix.risks.push({ id: tmUid('risk'), name, likelihood: tmRiskDraft.likelihood, impact: tmRiskDraft.impact, notes: tmRiskDraft.notes });
    tmRiskDraft = { name: '', likelihood: 3, impact: 3, notes: '' };
    renderRiskMatrixSection(container);
  });

  container.querySelectorAll('[data-scale]').forEach((inp) => {
    inp.addEventListener('input', () => {
      const [kind, level] = inp.getAttribute('data-scale').split(':');
      const arr = kind === 'likelihood' ? tmState.riskMatrix.likelihood : tmState.riskMatrix.impact;
      const entry = arr.find((x) => String(x.level) === level);
      if (entry) entry.label = inp.value;
      renderRiskMatrixGrid();
    });
  });

  function renderRiskMatrixGrid() {
    const gridEl = container.querySelector('#tm-risk-grid');
    const impactDesc = tmState.riskMatrix.impact.slice().sort((a, b) => b.level - a.level);
    const likelihoodAsc = tmState.riskMatrix.likelihood.slice().sort((a, b) => a.level - b.level);
    let html = '<table class="tm-matrix-table"><thead><tr><th></th>';
    for (const l of likelihoodAsc) html += `<th>${tmEsc(l.label)}<br><span class="muted" style="font-weight:400;">(${l.level})</span></th>`;
    html += '</tr></thead><tbody>';
    for (const im of impactDesc) {
      html += `<tr><th style="text-align:right;">${tmEsc(im.label)}<br><span class="muted" style="font-weight:400;">(${im.level})</span></th>`;
      for (const l of likelihoodAsc) {
        const rating = riskMatrixCellRating(l.level, im.level);
        const risksHere = tmState.riskMatrix.risks.filter((r) => r.likelihood === l.level && r.impact === im.level);
        html += `<td class="tm-matrix-cell" style="background:${rating.color}22; color:${rating.color};" title="${tmEsc(rating.label)}">${l.level * im.level}${risksHere.length ? `<div style="font-size:10px; color:#fff; margin-top:2px;">${risksHere.length} risk${risksHere.length > 1 ? 's' : ''}</div>` : ''}</td>`;
      }
      html += '</tr>';
    }
    html += '</tbody></table>';
    gridEl.innerHTML = html;
  }
  renderRiskMatrixGrid();

  const register = container.querySelector('#tm-risk-register');
  if (tmState.riskMatrix.risks.length === 0) {
    register.innerHTML = '<div class="tm-empty">No risks added yet.</div>';
  } else {
    const sorted = tmState.riskMatrix.risks.slice().sort((a, b) => (b.likelihood * b.impact) - (a.likelihood * a.impact));
    register.innerHTML = `
      <div class="tm-table-wrap">
        <table class="tm-table">
          <thead><tr><th>Risk</th><th>Likelihood</th><th>Impact</th><th>Score</th><th>Rating</th><th>Notes</th><th></th></tr></thead>
          <tbody>
            ${sorted.map((r) => {
              const rating = riskMatrixCellRating(r.likelihood, r.impact);
              const lLabel = tmState.riskMatrix.likelihood.find((l) => l.level === r.likelihood);
              const iLabel = tmState.riskMatrix.impact.find((i) => i.level === r.impact);
              return `
                <tr>
                  <td>${tmEsc(r.name)}</td>
                  <td>${lLabel ? tmEsc(lLabel.label) : r.likelihood}</td>
                  <td>${iLabel ? tmEsc(iLabel.label) : r.impact}</td>
                  <td class="mono">${r.likelihood * r.impact}</td>
                  <td><span class="tm-badge tm-badge-${rating.label.toLowerCase()}">${tmEsc(rating.label)}</span></td>
                  <td>${tmEsc(r.notes)}</td>
                  <td><button type="button" class="btn sm ghost" data-remove-risk="${r.id}">Remove</button></td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
    register.querySelectorAll('[data-remove-risk]').forEach((btn) => {
      btn.addEventListener('click', () => {
        tmState.riskMatrix.risks = tmState.riskMatrix.risks.filter((r) => r.id !== btn.getAttribute('data-remove-risk'));
        renderRiskMatrixSection(container);
      });
    });
  }

  container.querySelector('#tm-risk-export').addEventListener('click', () => {
    const header = ['Risk', 'Likelihood', 'Impact', 'Score', 'Rating', 'Notes'];
    const rows = tmState.riskMatrix.risks.map((r) => {
      const rating = riskMatrixCellRating(r.likelihood, r.impact);
      return [r.name, r.likelihood, r.impact, r.likelihood * r.impact, rating.label, r.notes].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',');
    });
    tmDownload('risk-matrix.csv', [header.join(','), ...rows].join('\n'));
  });
}

/* ============================================================================
   SECTION 28: SECURITY REQUIREMENTS GENERATOR SECTION
   ========================================================================== */

function tmSelectedThreatsList() {
  return tmAllThreatsFlat().filter((t) => tmState.threatLibrary.selected[t.id]);
}

function tmGenerateRequirementsForSelection() {
  const selected = tmSelectedThreatsList();
  const categoriesPresent = new Set(selected.map((t) => t.category));
  const requirements = [];
  for (const cat of categoriesPresent) {
    const templates = SECURITY_REQUIREMENTS_TEMPLATES[cat] || [];
    for (const t of templates) requirements.push({ ...t, category: cat });
  }
  return requirements;
}

function renderSecurityRequirementsSection(container) {
  const selected = tmSelectedThreatsList();
  const requirements = tmGenerateRequirementsForSelection();

  container.innerHTML = `
    <div class="panel">
      <h2 class="pg-h2">Security Requirements Generator</h2>
      <p class="muted" style="max-width:760px;">Generates concrete, testable security requirements from the threats you selected in the Threat Library. Requirements are grouped by STRIDE category and include a suggested verification method so they can be tracked through to acceptance testing.</p>
    </div>

    ${selected.length === 0 ? `
      <div class="card tm-empty">
        No threats selected yet. Go to the <b>Threat Library</b> tab and check "Select for security requirements" on any relevant threats, then return here.
        <div style="margin-top:10px;"><button type="button" class="btn sm ghost" data-goto-lib="1">Go to Threat Library</button></div>
      </div>
    ` : `
      <div class="tm-grid tm-grid-6" style="margin-bottom:6px;">
        <div class="stat"><div class="stat-n">${selected.length}</div><div class="stat-l">Threats Selected</div></div>
        <div class="stat"><div class="stat-n">${requirements.length}</div><div class="stat-l">Requirements Generated</div></div>
        <div class="stat"><div class="stat-n">${requirements.filter((r) => r.priority === 'Critical').length}</div><div class="stat-l">Critical Priority</div></div>
        <div class="stat"><div class="stat-n">${requirements.filter((r) => r.priority === 'High').length}</div><div class="stat-l">High Priority</div></div>
      </div>

      <div class="panel">
        <div class="tm-flex-between">
          <h3 style="margin:0;">Selected Threats</h3>
        </div>
        <div class="tm-table-wrap">
          <table class="tm-table">
            <thead><tr><th>ID</th><th>Category</th><th>Threat</th><th>Severity</th></tr></thead>
            <tbody>${selected.map((t) => `<tr><td class="mono">${tmEsc(t.id)}</td><td>${tmEsc(TM_STRIDE_LABELS[t.category])}</td><td>${tmEsc(t.title)}</td><td><span class="tm-badge tm-badge-${t.severity.toLowerCase()}">${tmEsc(t.severity)}</span></td></tr>`).join('')}</tbody>
          </table>
        </div>
      </div>

      <div class="panel">
        <div class="tm-flex-between">
          <h3 style="margin:0;">Generated Requirements (${requirements.length})</h3>
          <button type="button" class="btn sm ghost" id="tm-req-export">Export CSV</button>
        </div>
        <div class="tm-table-wrap">
          <table class="tm-table">
            <thead><tr><th>ID</th><th>Category</th><th>Requirement</th><th>Priority</th><th>Verification</th></tr></thead>
            <tbody>
              ${requirements.map((r) => `
                <tr>
                  <td class="mono">${tmEsc(r.id)}</td>
                  <td>${tmEsc(TM_STRIDE_LABELS[r.category])}</td>
                  <td>${tmEsc(r.requirement)}</td>
                  <td><span class="tm-badge tm-badge-${r.priority.toLowerCase()}">${tmEsc(r.priority)}</span></td>
                  <td>${tmEsc(r.verification)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `}
  `;

  const gotoBtn = container.querySelector('[data-goto-lib]');
  if (gotoBtn) {
    gotoBtn.addEventListener('click', () => {
      tmState.activeTab = 'library';
      const tabBar = document.getElementById('tm-tab-bar');
      if (tabBar) tabBar.querySelectorAll('[data-tab]').forEach((b) => b.classList.toggle('active', b.getAttribute('data-tab') === 'library'));
      const content = document.getElementById('tm-tab-content');
      if (content) { content.innerHTML = ''; renderThreatLibrarySection(content); }
    });
  }

  const exportBtn = container.querySelector('#tm-req-export');
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      const header = ['ID', 'Category', 'Requirement', 'Priority', 'Verification'];
      const rows = requirements.map((r) => [r.id, TM_STRIDE_LABELS[r.category], r.requirement, r.priority, r.verification].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(','));
      tmDownload('security-requirements.csv', [header.join(','), ...rows].join('\n'));
    });
  }
}

/* ============================================================================
   SECTION 29: COMPLIANCE MAPPING SECTION
   ========================================================================== */

function renderComplianceSection(container) {
  const cat = tmState.compliance.selectedCategory;
  const map = STRIDE_COMPLIANCE_MAP[cat];

  container.innerHTML = `
    <div class="panel">
      <h2 class="pg-h2">Compliance Mapping</h2>
      <p class="muted" style="max-width:760px;">Maps each STRIDE threat category to relevant controls in NIST SP 800-53 Rev. 5, ISO/IEC 27001:2022 Annex A, and CIS Controls v8. Use this to demonstrate to auditors that identified threats are addressed by your existing control framework, or to identify control gaps.</p>
    </div>

    <div class="tm-section-nav" id="tm-comp-cats"></div>

    <div class="panel">
      <div class="tm-flex-between">
        <h3 style="margin:0;">${tmEsc(TM_STRIDE_LABELS[cat])} -- Control Mapping</h3>
      </div>
      <p style="font-size:13px; line-height:1.6;">${tmEsc(map.rationale)}</p>
      <div class="tm-grid tm-grid-3" style="margin-top:12px;">
        <div>
          <h4 style="margin-bottom:6px;">NIST SP 800-53 Rev. 5</h4>
          ${map.nist.map((id) => {
            const c = NIST_800_53_CONTROLS.find((x) => x.id === id);
            return c ? `<div class="tm-threat-card" style="margin-bottom:8px;"><div class="mono" style="font-size:12px; font-weight:700;">${tmEsc(c.id)}</div><div style="font-size:13px; font-weight:600;">${tmEsc(c.title)}</div><div style="font-size:12px; opacity:.75; margin-top:2px;">${tmEsc(c.description)}</div></div>` : '';
          }).join('')}
        </div>
        <div>
          <h4 style="margin-bottom:6px;">ISO/IEC 27001:2022 Annex A</h4>
          ${map.iso.map((id) => {
            const c = ISO_27001_CONTROLS.find((x) => x.id === id);
            return c ? `<div class="tm-threat-card" style="margin-bottom:8px;"><div class="mono" style="font-size:12px; font-weight:700;">${tmEsc(c.id)}</div><div style="font-size:13px; font-weight:600;">${tmEsc(c.title)}</div><div style="font-size:12px; opacity:.75; margin-top:2px;">${tmEsc(c.description)}</div></div>` : '';
          }).join('')}
        </div>
        <div>
          <h4 style="margin-bottom:6px;">CIS Controls v8</h4>
          ${map.cis.map((id) => {
            const c = CIS_CONTROLS_V8.find((x) => x.id === id);
            return c ? `<div class="tm-threat-card" style="margin-bottom:8px;"><div class="mono" style="font-size:12px; font-weight:700;">${tmEsc(c.id)}</div><div style="font-size:13px; font-weight:600;">${tmEsc(c.title)}</div><div style="font-size:12px; opacity:.75; margin-top:2px;">${tmEsc(c.description)}</div></div>` : '';
          }).join('')}
        </div>
      </div>
    </div>

    <div class="panel">
      <h3 style="margin-top:0;">Full Control Reference</h3>
      <div class="tab-bar" id="tm-comp-framework-tabs"></div>
      <div id="tm-comp-framework-body"></div>
    </div>
  `;

  const catNav = container.querySelector('#tm-comp-cats');
  catNav.innerHTML = Object.keys(TM_STRIDE_LABELS).map((k) => `<button type="button" class="tm-pill${k === cat ? ' active' : ''}" data-comp-cat="${k}">${TM_STRIDE_LABELS[k]}</button>`).join('');
  catNav.querySelectorAll('[data-comp-cat]').forEach((btn) => {
    btn.addEventListener('click', () => {
      tmState.compliance.selectedCategory = btn.getAttribute('data-comp-cat');
      renderComplianceSection(container);
    });
  });

  const fwTabs = container.querySelector('#tm-comp-framework-tabs');
  const frameworks = [{ key: 'nist', label: 'NIST 800-53' }, { key: 'iso', label: 'ISO 27001' }, { key: 'cis', label: 'CIS Controls v8' }];
  fwTabs.innerHTML = frameworks.map((f) => `<button type="button" class="tab${tmState.compliance.framework === f.key ? ' active' : ''}" data-fw="${f.key}">${f.label}</button>`).join('');
  fwTabs.querySelectorAll('[data-fw]').forEach((btn) => {
    btn.addEventListener('click', () => {
      tmState.compliance.framework = btn.getAttribute('data-fw');
      renderComplianceSection(container);
    });
  });

  const fwBody = container.querySelector('#tm-comp-framework-body');
  let list, cols;
  if (tmState.compliance.framework === 'nist') { list = NIST_800_53_CONTROLS; cols = ['ID', 'Family', 'Title', 'Description']; }
  else if (tmState.compliance.framework === 'iso') { list = ISO_27001_CONTROLS; cols = ['ID', 'Title', 'Description']; }
  else { list = CIS_CONTROLS_V8; cols = ['ID', 'Title', 'Description']; }

  fwBody.innerHTML = `
    <div class="tm-table-wrap">
      <table class="tm-table">
        <thead><tr>${cols.map((c) => `<th>${c}</th>`).join('')}</tr></thead>
        <tbody>
          ${list.map((c) => `
            <tr>
              <td class="mono" style="white-space:nowrap;">${tmEsc(c.id)}</td>
              ${c.family ? `<td>${tmEsc(c.family)}</td>` : ''}
              <td style="font-weight:600; white-space:nowrap;">${tmEsc(c.title)}</td>
              <td>${tmEsc(c.description)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

/*__APPEND_MARK__*/
