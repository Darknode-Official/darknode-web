// dlp-engine.js — pure, deterministic Data Loss Prevention scanner.
// Detects secrets + PII in free text, fully client-side. No network, no state.
// Every detector is exported and unit-tested; see test/security/dlp.test.mjs.

// ---- low-level helpers ----------------------------------------------------

// Luhn check for payment card numbers.
export function luhnValid(digits) {
  const s = String(digits).replace(/\D/g, '');
  if (s.length < 12 || s.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = s.length - 1; i >= 0; i--) {
    let d = s.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}

// Card brand from the (digits-only) PAN.
export function cardBrand(pan) {
  const s = String(pan).replace(/\D/g, '');
  if (/^4\d{12}(\d{3})?(\d{3})?$/.test(s)) return 'Visa';
  if (/^(5[1-5]\d{14}|2(2[2-9]\d{12}|[3-6]\d{13}|7[01]\d{12}|720\d{12}))$/.test(s)) return 'Mastercard';
  if (/^3[47]\d{13}$/.test(s)) return 'American Express';
  if (/^(6011\d{12}|65\d{14}|64[4-9]\d{13})$/.test(s)) return 'Discover';
  if (/^3(0[0-5]\d{11}|[68]\d{12})$/.test(s)) return 'Diners Club';
  if (/^(352[89]|35[3-8]\d)\d{12}$/.test(s)) return 'JCB';
  return 'Card';
}

// IBAN mod-97 (ISO 13616) with a per-country length table.
const IBAN_LEN = {
  AD:24,AE:23,AL:28,AT:20,AZ:28,BA:20,BE:16,BG:22,BH:22,BR:29,BY:28,CH:21,CR:22,
  CY:28,CZ:24,DE:22,DK:18,DO:28,EE:20,EG:29,ES:24,FI:18,FO:18,FR:27,GB:22,GE:22,
  GI:23,GL:18,GR:27,GT:28,HR:21,HU:28,IE:22,IL:23,IQ:23,IS:26,IT:27,JO:30,KW:30,
  KZ:20,LB:28,LC:32,LI:21,LT:20,LU:20,LV:21,MC:27,MD:24,ME:22,MK:19,MR:27,MT:31,
  MU:30,NL:18,NO:15,PK:24,PL:28,PS:29,PT:25,QA:29,RO:24,RS:22,SA:24,SC:31,SE:24,
  SI:19,SK:24,SM:27,TN:24,TR:26,UA:29,VA:22,VG:24,XK:20,
};
export function ibanValid(raw) {
  const s = String(raw).replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(s)) return false;
  const cc = s.slice(0, 2);
  if (IBAN_LEN[cc] && s.length !== IBAN_LEN[cc]) return false;
  const re = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of re) {
    const v = ch >= 'A' && ch <= 'Z' ? ch.charCodeAt(0) - 55 : ch.charCodeAt(0) - 48;
    rem = (rem * (v > 9 ? 100 : 10) + v) % 97;
  }
  return rem === 1;
}

// US SSN structural validity (not just the mask).
export function ssnValid(raw) {
  const m = String(raw).replace(/[\s-]/g, '');
  if (!/^\d{9}$/.test(m)) return false;
  const area = m.slice(0, 3), group = m.slice(3, 5), serial = m.slice(5);
  if (area === '000' || area === '666' || area[0] === '9') return false;
  if (group === '00') return false;
  if (serial === '0000') return false;
  return true;
}

// Shannon entropy in bits/char — used to separate real tokens from prose.
export function shannonEntropy(str) {
  if (!str) return 0;
  const freq = Object.create(null);
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let H = 0;
  const n = str.length;
  for (const k in freq) { const p = freq[k] / n; H -= p * Math.log2(p); }
  return H;
}

// Mask a value, keeping only the tail (or a short head+tail) visible.
export function maskValue(v, keepTail = 4) {
  const s = String(v);
  if (s.length <= keepTail) return '•'.repeat(s.length);
  if (s.length <= 10) return '•'.repeat(s.length - keepTail) + s.slice(-keepTail);
  return s.slice(0, 2) + '•'.repeat(Math.max(4, s.length - 6)) + s.slice(-keepTail);
}

// ---- detector catalogue ---------------------------------------------------
// severity: critical > high > medium > low. `validate` gates regex hits.

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

export const DETECTORS = [
  {
    id: 'private-key', label: 'Private key', kind: 'secret', severity: 'critical',
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    mask: () => '[PRIVATE KEY BLOCK]',
    advice: 'Revoke and rotate this key immediately; it grants direct access.',
  },
  {
    id: 'aws-secret', label: 'AWS secret access key', kind: 'secret', severity: 'critical',
    re: /\b(?:aws)?_?(?:secret)?_?access_?key["'\s:=]{1,6}([A-Za-z0-9/+=]{40})\b/gi,
    group: 1,
    validate: (m) => shannonEntropy(m) >= 4.0,
    advice: 'Rotate the AWS secret key and audit CloudTrail for misuse.',
  },
  {
    id: 'aws-key', label: 'AWS access key ID', kind: 'secret', severity: 'high',
    re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b/g,
    advice: 'Deactivate the access key ID in IAM and rotate its secret.',
  },
  {
    id: 'gcp-key', label: 'Google API key', kind: 'secret', severity: 'high',
    re: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    advice: 'Restrict or regenerate the Google API key in the Cloud console.',
  },
  {
    id: 'github-token', label: 'GitHub token', kind: 'secret', severity: 'critical',
    re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g,
    advice: 'Revoke the GitHub token in developer settings now.',
  },
  {
    id: 'github-pat-fine', label: 'GitHub fine-grained token', kind: 'secret', severity: 'critical',
    re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g,
    advice: 'Revoke this fine-grained personal access token immediately.',
  },
  {
    id: 'slack-token', label: 'Slack token', kind: 'secret', severity: 'high',
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    advice: 'Revoke the Slack token in the app management console.',
  },
  {
    id: 'stripe-key', label: 'Stripe live key', kind: 'secret', severity: 'critical',
    re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g,
    advice: 'Roll the Stripe live key in the dashboard immediately.',
  },
  {
    id: 'openai-key', label: 'OpenAI API key', kind: 'secret', severity: 'high',
    re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    validate: (m) => shannonEntropy(m) >= 3.5,
    advice: 'Revoke the OpenAI key in the API dashboard.',
  },
  {
    id: 'anthropic-key', label: 'Anthropic API key', kind: 'secret', severity: 'high',
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    advice: 'Revoke the Anthropic key in the console.',
  },
  {
    id: 'google-oauth', label: 'Google OAuth client secret', kind: 'secret', severity: 'high',
    re: /\bGOCSPX-[A-Za-z0-9_-]{20,}\b/g,
    advice: 'Rotate the OAuth client secret in the Cloud console.',
  },
  {
    id: 'jwt', label: 'JSON Web Token', kind: 'secret', severity: 'medium',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    advice: 'Treat the JWT as a live credential until it expires; do not share it.',
  },
  {
    id: 'slack-webhook', label: 'Slack webhook URL', kind: 'secret', severity: 'medium',
    re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g,
    advice: 'Regenerate the incoming webhook; anyone with the URL can post.',
  },
  {
    id: 'twilio-key', label: 'Twilio account SID', kind: 'secret', severity: 'medium',
    re: /\bAC[a-f0-9]{32}\b/g,
    advice: 'Pair with the auth token; rotate the Twilio auth token if exposed.',
  },
  {
    id: 'sendgrid-key', label: 'SendGrid API key', kind: 'secret', severity: 'high',
    re: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g,
    advice: 'Delete and recreate the SendGrid key.',
  },
  {
    id: 'pat-assignment', label: 'Password or secret in assignment', kind: 'secret', severity: 'high',
    re: /\b(?:passwd|password|pwd|secret|token|api[_-]?key|access[_-]?token|client[_-]?secret)\b["'\s]*[:=]\s*["']([^"'\s]{6,})["']/gi,
    group: 1,
    validate: (m) => !(/(?:your[_-]?|changeme|example|placeholder|redacted|dummy|sample|foobar|test[_-]?(?:key|token|secret)|xxx|\*\*\*|here\b)/i.test(m) || /^(?:<[^>]+>|\$\{?[a-z_]+\}?|%[a-z_]+%|null|none|true|false)$/i.test(m) || /^(.)\1+$/.test(m)),
    advice: 'Move the secret to a secrets manager or environment variable.',
  },
  {
    id: 'credit-card', label: 'Payment card number', kind: 'pii', severity: 'high',
    re: /\b(?:\d[ -]?){13,19}\b/g,
    validate: (m) => luhnValid(m),
    detail: (m) => cardBrand(m),
    advice: 'Never store full PANs; tokenise or truncate per PCI DSS.',
  },
  {
    id: 'iban', label: 'IBAN (bank account)', kind: 'pii', severity: 'medium',
    re: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,8}[ ]?[A-Z0-9]{0,3}\b/g,
    validate: (m) => ibanValid(m),
    advice: 'Bank account numbers are financial PII; restrict access.',
  },
  {
    id: 'ssn', label: 'US Social Security number', kind: 'pii', severity: 'high',
    re: /\b\d{3}-\d{2}-\d{4}\b/g,
    validate: (m) => ssnValid(m),
    advice: 'SSNs are highly sensitive PII; encrypt and minimise retention.',
  },
  {
    id: 'email', label: 'Email address', kind: 'pii', severity: 'low',
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    validate: (m) => !/\.(png|jpg|jpeg|gif|svg|webp|css|js|json|html)$/i.test(m),
    advice: 'Email addresses are personal data under GDPR/CCPA.',
  },
  {
    id: 'ipv4', label: 'IPv4 address', kind: 'pii', severity: 'low',
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    validate: (m, _whole, ctx) => {
      const o = m.split('.');
      if (o[0] === '0' || o[0] === '127') return false; // always skip these (current behavior)
      const opts = (ctx && ctx.opts) || {};
      if (!opts.excludePrivateIp) return true; // default: flag everything else
      // opted in to noise reduction: ignore version strings and private ranges
      if (ctx && typeof ctx.index === 'number' && typeof ctx.text === 'string') {
        const before = ctx.text.slice(Math.max(0, ctx.index - 12), ctx.index);
        const after = ctx.text.slice(ctx.index + m.length, ctx.index + m.length + 2);
        if (/\b(?:version|ver|rev|release|build)\s*$/i.test(before)) return false;
        if (before.endsWith('.')) return false;      // continuation of a longer dotted number
        if (/^\.\d/.test(after)) return false;        // more octets follow → not an IPv4
      }
      const a = +o[0], b = +o[1];
      if (a === 10) return false;                       // 10.0.0.0/8
      if (a === 172 && b >= 16 && b <= 31) return false; // 172.16.0.0/12
      if (a === 192 && b === 168) return false;         // 192.168.0.0/16
      if (a === 169 && b === 254) return false;         // 169.254.0.0/16 link-local
      return true;
    },
    advice: 'Internal IPs can reveal topology; redact in public documents.',
  },
  {
    id: 'us-phone', label: 'US phone number', kind: 'pii', severity: 'low',
    re: /(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b/g,
    // NANP sanity: 10 digits (or 11 with a leading 1); area-code and exchange
    // first digits must be 2-9. Rejects arbitrary \d{3}-\d{3}-\d{4} digit runs.
    validate: (m) => { let n = m.replace(/\D/g, ''); if (n.length === 11 && n[0] === '1') n = n.slice(1); return n.length === 10 && n[0] >= '2' && n[3] >= '2'; },
    advice: 'Phone numbers are personal data; mask where not needed.',
  },
  {
    id: 'conn-string', label: 'Database connection string', kind: 'secret', severity: 'critical',
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s:@/]+@[^\s/]+/gi,
    mask: (m) => m.replace(/:\/\/([^:]+):[^@]+@/, '://$1:••••••@'),
    advice: 'Embedded DB credentials are exposed; rotate and use a secrets store.',
  },
  {
    id: 'azure-storage-key', label: 'Azure Storage account key', kind: 'secret', severity: 'critical',
    re: /AccountKey=([A-Za-z0-9+/]{86}==)/g,
    group: 1,
    advice: 'Rotate the storage account key in the Azure portal; it grants full access.',
  },
  {
    id: 'azure-sas', label: 'Azure SAS token', kind: 'secret', severity: 'high',
    re: /[?&]sv=\d{4}-\d{2}-\d{2}&[^\s"'<>]*?sig=[A-Za-z0-9%]{10,}/gi,
    mask: () => '[AZURE SAS TOKEN]',
    advice: 'Revoke the shared access signature; anyone with the URL has the granted access.',
  },
  {
    id: 'azure-ad-secret', label: 'Azure AD client secret', kind: 'secret', severity: 'critical',
    re: /\b[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34}\b/g,
    advice: 'Rotate the app registration client secret in Entra ID / Azure AD.',
  },
  {
    id: 'gitlab-pat', label: 'GitLab personal access token', kind: 'secret', severity: 'critical',
    re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    advice: 'Revoke the GitLab token under User Settings → Access Tokens.',
  },
  {
    id: 'npm-token', label: 'npm access token', kind: 'secret', severity: 'high',
    re: /\bnpm_[A-Za-z0-9]{36}\b/g,
    advice: 'Revoke the npm token with `npm token revoke` or in your npm account.',
  },
  {
    id: 'gcp-service-account', label: 'GCP service-account key', kind: 'secret', severity: 'critical',
    re: /-----BEGIN PRIVATE KEY-----[\s\S]{0,4000}?\.iam\.gserviceaccount\.com/g,
    mask: () => '[GCP SERVICE ACCOUNT KEY]',
    advice: 'Delete this service-account key in IAM and generate a fresh one; it grants API access.',
  },
  {
    id: 'heroku-key', label: 'Heroku API key', kind: 'secret', severity: 'high',
    re: /\bheroku[^\n]{0,40}?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/gi,
    group: 1,
    advice: 'Regenerate the Heroku API key with `heroku authorizations:rotate`.',
  },
  {
    id: 'digitalocean-token', label: 'DigitalOcean token', kind: 'secret', severity: 'critical',
    re: /\bdo[opr]_v1_[a-f0-9]{64}\b/g,
    advice: 'Revoke the DigitalOcean token in the API section of the control panel.',
  },
  {
    id: 'bearer-auth', label: 'Bearer / Authorization token', kind: 'secret', severity: 'high',
    re: /\b(?:Authorization:\s*)?(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{16,})/g,
    group: 1,
    validate: (m) => !/^(?:your|example|placeholder|token|changeme|xxx|redacted)/i.test(m) && !/^(.)\1+$/.test(m),
    advice: 'Treat this header credential as live; rotate it and do not log Authorization headers.',
  },
  {
    id: 'mailgun-key', label: 'Mailgun API key', kind: 'secret', severity: 'high',
    re: /\bkey-[0-9a-f]{32}\b/gi,
    advice: 'Rotate the Mailgun API key in the control panel.',
  },
  {
    id: 'planetscale-token', label: 'PlanetScale token', kind: 'secret', severity: 'critical',
    re: /\bpscale_(?:tkn|pw|oauth)_[A-Za-z0-9._-]{32,}/g,
    advice: 'Revoke the PlanetScale password/token in the database settings.',
  },
  {
    id: 'slack-app-token', label: 'Slack app-level token', kind: 'secret', severity: 'high',
    re: /\bxapp-\d-[A-Za-z0-9]+-\d+-[a-z0-9]+\b/gi,
    advice: 'Revoke the Slack app-level token in the app management console.',
  },
];

// ---- generic high-entropy sweep (after the named detectors) ---------------

const ENTROPY_MIN_LEN = 24;
const ENTROPY_B64 = 4.2;   // bits/char threshold for base64-ish blobs
const ENTROPY_HEX = 3.0;   // hex alphabet tops out near 4 bits/char

function looksLikeWords(tok) {
  // Reject tokens that are really joined English (low digit/mixed-case mix).
  return /^[A-Za-z]+$/.test(tok) || /^[A-Za-z]+(?:[._-][A-Za-z]+)+$/.test(tok);
}

export function scanEntropy(text, alreadyFound, opts = {}) {
  const hits = [];
  const taken = alreadyFound || [];
  const b64Need = Number.isFinite(opts.entropyThreshold) ? opts.entropyThreshold : ENTROPY_B64;
  const covers = (i, j) => taken.some((f) => i < f.end && j > f.start);
  const re = /[A-Za-z0-9+/=_-]{24,}/g;
  let m;
  while ((m = re.exec(text))) {
    const tok = m[0];
    if (looksLikeWords(tok)) continue;
    if (tok.length < ENTROPY_MIN_LEN) continue;
    const isHex = /^[a-f0-9]+$/i.test(tok);
    const H = shannonEntropy(tok);
    const need = isHex ? ENTROPY_HEX : b64Need;
    if (H < need) continue;
    if (isHex && tok.length < 32) continue; // short hex is often an id, not a secret
    const start = m.index, end = m.index + tok.length;
    if (covers(start, end)) continue;
    hits.push({
      id: 'high-entropy', label: 'High-entropy token (possible secret)', kind: 'secret',
      severity: 'medium', value: tok, masked: maskValue(tok), start, end,
      entropy: Math.round(H * 100) / 100,
      detail: isHex ? 'hex' : 'base64',
      advice: 'Looks like a key or token; confirm and move it to a secrets store.',
    });
  }
  return hits;
}

// ---- line/column mapping --------------------------------------------------

function lineIndex(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1);
  return starts;
}
function locate(starts, pos) {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= pos) lo = mid; else hi = mid - 1; }
  return { line: lo + 1, col: pos - starts[lo] + 1 };
}

// ---- main scan ------------------------------------------------------------

export function scan(text, opts = {}) {
  text = String(text || '');
  const enabled = opts.detectors ? new Set(opts.detectors) : null;
  const found = [];

  for (const det of DETECTORS) {
    if (enabled && !enabled.has(det.id)) continue;
    det.re.lastIndex = 0;
    let m;
    while ((m = det.re.exec(text))) {
      const whole = m[0];
      const value = det.group ? m[det.group] : whole;
      if (!value) { if (m.index === det.re.lastIndex) det.re.lastIndex++; continue; }
      // anchor on the captured value's position within the match
      const vOff = det.group ? whole.indexOf(value) : 0;
      const start = m.index + (vOff < 0 ? 0 : vOff);
      const end = start + value.length;
      if (det.validate && !det.validate(value, whole, { opts, text, index: start })) continue;
      found.push({
        id: det.id, label: det.label, kind: det.kind, severity: det.severity,
        value, masked: det.mask ? det.mask(value) : maskValue(value),
        start, end,
        detail: det.detail ? det.detail(value) : '',
        advice: det.advice,
      });
      if (m.index === det.re.lastIndex) det.re.lastIndex++;
    }
  }

  // de-dup overlapping named hits: keep the higher-severity / longer one
  found.sort((a, b) => a.start - b.start || (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0));
  const kept = [];
  for (const f of found) {
    const clash = kept.find((k) => f.start < k.end && f.end > k.start);
    if (!clash) { kept.push(f); continue; }
    if (SEV_RANK[f.severity] > SEV_RANK[clash.severity] ||
        (SEV_RANK[f.severity] === SEV_RANK[clash.severity] && (f.end - f.start) > (clash.end - clash.start))) {
      kept[kept.indexOf(clash)] = f;
    }
  }

  let all = kept;
  if (!enabled || enabled.has('high-entropy')) {
    all = kept.concat(scanEntropy(text, kept, opts));
  }
  all.sort((a, b) => a.start - b.start);

  const starts = lineIndex(text);
  for (const f of all) {
    const loc = locate(starts, f.start);
    f.line = loc.line; f.col = loc.col;
  }

  return summarize(all, text);
}

function summarize(findings, text) {
  const byType = {}, bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    byType[f.id] = byType[f.id] || { id: f.id, label: f.label, kind: f.kind, severity: f.severity, count: 0 };
    byType[f.id].count++;
    bySeverity[f.severity]++;
  }
  const score = bySeverity.critical * 100 + bySeverity.high * 25 + bySeverity.medium * 8 + bySeverity.low * 1;
  let grade = 'clean';
  if (bySeverity.critical) grade = 'critical';
  else if (bySeverity.high) grade = 'high';
  else if (bySeverity.medium) grade = 'elevated';
  else if (bySeverity.low) grade = 'low';
  return {
    findings,
    counts: { total: findings.length, secrets: findings.filter((f) => f.kind === 'secret').length, pii: findings.filter((f) => f.kind === 'pii').length },
    bySeverity,
    byType: Object.values(byType).sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || b.count - a.count),
    score, grade,
    bytes: text.length,
  };
}

// Produce a redacted copy of the text with each finding replaced.
export function redact(text, findings, style = 'label') {
  text = String(text || '');
  const sorted = [...findings].sort((a, b) => b.start - a.start);
  let out = text;
  for (const f of sorted) {
    const token = style === 'mask' ? f.masked
      : style === 'block' ? '█'.repeat(Math.max(3, Math.min(12, f.end - f.start)))
      : `[REDACTED:${f.id}]`;
    out = out.slice(0, f.start) + token + out.slice(f.end);
  }
  return out;
}

// ---- self-test ------------------------------------------------------------

export function selfTest() {
  const out = [];
  const T = (name, cond) => out.push({ name, pass: !!cond });

  T('luhn visa', luhnValid('4111111111111111'));
  T('luhn reject', !luhnValid('4111111111111112'));
  T('iban de', ibanValid('DE89 3704 0044 0532 0130 00'));
  T('iban reject', !ibanValid('DE89 3704 0044 0532 0130 01'));
  T('ssn valid', ssnValid('123-45-6789'));
  T('ssn reject 000 area', !ssnValid('000-45-6789'));
  T('entropy prose low', shannonEntropy('the quick brown fox') < 4.3);

  const r = scan([
    'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    'AKIAIOSFODNN7EXAMPLE',
    'card 4111 1111 1111 1111',
    'ssn 123-45-6789',
    'contact jane@example.com',
    '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----',
    'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789',
  ].join('\n'));
  T('found aws key id', r.findings.some((f) => f.id === 'aws-key'));
  T('found card', r.findings.some((f) => f.id === 'credit-card' && f.detail === 'Visa'));
  T('found ssn', r.findings.some((f) => f.id === 'ssn'));
  T('found email', r.findings.some((f) => f.id === 'email'));
  T('found private key', r.findings.some((f) => f.id === 'private-key'));
  T('found github token', r.findings.some((f) => f.id === 'github-token'));
  T('critical counted', r.bySeverity.critical >= 1);

  const r2 = scan([
    'glpat-ABCDEFGHIJ0123456789',
    'npm_' + 'a'.repeat(36),
    'dop_v1_' + 'a'.repeat(64),
    'Authorization: Bearer abcDEF123ghiJKL456mno',
    'AccountKey=' + 'A'.repeat(86) + '==',
    'mykey=key-' + '0123456789abcdef'.repeat(2),
    'xapp-1-ABC123-1234567890-abcdef0123456789',
  ].join('\n'));
  T('found gitlab pat', r2.findings.some((f) => f.id === 'gitlab-pat'));
  T('found npm token', r2.findings.some((f) => f.id === 'npm-token'));
  T('found digitalocean token', r2.findings.some((f) => f.id === 'digitalocean-token'));
  T('found bearer token', r2.findings.some((f) => f.id === 'bearer-auth'));
  T('found azure storage key', r2.findings.some((f) => f.id === 'azure-storage-key'));
  T('found mailgun key', r2.findings.some((f) => f.id === 'mailgun-key'));
  T('found slack app token', r2.findings.some((f) => f.id === 'slack-app-token'));
  T('private-ip allowlist drops 10/8', !scan('host 10.1.2.3 here', { excludePrivateIp: true }).findings.some((f) => f.id === 'ipv4'));
  T('private-ip allowlist keeps public', scan('host 8.8.8.8 here', { excludePrivateIp: true }).findings.some((f) => f.id === 'ipv4'));
  T('ipv4 flagged by default', scan('host 10.1.2.3 here').findings.some((f) => f.id === 'ipv4'));
  T('redaction removes card', !redact('card 4111 1111 1111 1111', scan('card 4111 1111 1111 1111').findings).includes('4111 1111 1111 1111'));

  return { pass: out.every((t) => t.pass), tests: out };
}

export default { scan, redact, selfTest, DETECTORS, luhnValid, ibanValid, ssnValid, shannonEntropy, maskValue, cardBrand };
