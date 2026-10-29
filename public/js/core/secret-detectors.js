// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Shared secret-detector catalogue: one regex per credential type, used by the DLP
// scanner (dataprotect/dlp-engine.js, and through it LEAKPROBE), the Code Scanner
// (codescan/rules.js, also run by the Node CLI and the GitHub Action), the IaC
// scanner (appsec/iacscan-engine.js) and the Credential Auditor's key scanner.
//
// Pure and dependency-free (no DOM, no network, relative imports only) so it loads
// in the browser, in Blob Workers and in Node. Each consumer keeps its own ids,
// labels and severities through a small adapter; this file only says what a secret
// looks like.
//
// Detector fields:
//   id        stable id (the DLP engine's ids where it had one)
//   name      human label
//   severity  default severity (critical | high | medium | low); consumers may remap
//   re        global regex; the secret value is capture group `g` (or the whole match)
//   g         capture group of the value, or an array of alternative groups
//   validate  optional (value, whole, ctx) => boolean gate on a regex hit
//   mask      optional (value) => masked display string (default maskValue)
//   advice    one-line remediation

// Shannon entropy in bits/char: separates random tokens from words.
export function shannonEntropy(str) {
  if (!str) return 0;
  const freq = Object.create(null);
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let H = 0;
  const n = str.length;
  for (const k in freq) { const p = freq[k] / n; H -= p * Math.log2(p); }
  return H;
}

// Mask a value, keeping only the tail (or a short head + tail) visible.
export function maskValue(v, keepTail = 4) {
  const s = String(v);
  if (s.length <= keepTail) return '•'.repeat(s.length);
  if (s.length <= 10) return '•'.repeat(s.length - keepTail) + s.slice(-keepTail);
  return s.slice(0, 2) + '•'.repeat(Math.max(4, s.length - 6)) + s.slice(-keepTail);
}

// Placeholder / documentation values that are not real credentials.
export const PLACEHOLDER_VALUE = /(?:your[_-]?|changeme|example|placeholder|redacted|dummy|sample|foobar|test[_-]?(?:key|token|secret)|xxx|\*\*\*|here\b)/i;
const NOT_A_VALUE = /^(?:<[^>]+>|\$\{?[a-z_]+\}?|%[a-z_]+%|null|none|true|false)$/i;
const realValue = (m) => !(PLACEHOLDER_VALUE.test(m) || NOT_A_VALUE.test(m) || /^(.)\1+$/.test(m));

// Key names that hold a credential in `name = "value"` assignments.
export const SECRET_KEY_WORDS = /^(?:passwd|password|pwd|secret|token|api[_-]?key|apikey|access[_-]?(?:key|token)|auth[_-]?key|client[_-]?secret)$/i;

/**
 * True when assignment key `key` ends in a credential word (SECRET_KEY_WORDS) that starts
 * the key or follows one of the separator characters `seps`: "db.password" and
 * "my-api-key" hold a secret, "password_hash" does not.
 */
export function keyHoldsSecret(key, seps = '.-') {
  const k = String(key || '');
  for (let i = 0; i < k.length; i++) if ((i === 0 || seps.includes(k[i - 1])) && SECRET_KEY_WORDS.test(k.slice(i))) return true;
  return false;
}
/** The key name of a pat-assignment match (the text before the separator). */
export const assignmentKey = (whole) => (/^[A-Za-z0-9_.-]+/.exec(String(whole || '')) || [''])[0];

// The value must stop here: end of text, whitespace, a quote or a closing delimiter.
const END = String.raw`(?![^\s"'\x60,;)}\]])`;
const PEM_TYPES = '(?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?';

export const SECRET_DETECTORS = [
  {
    id: 'private-key', name: 'Private key', severity: 'critical',
    // The header alone (line-oriented scanners); BLOCK_RE below spans BEGIN..END.
    re: new RegExp(`-----BEGIN ${PEM_TYPES}PRIVATE KEY(?: BLOCK)?-----`, 'g'),
    mask: () => '[PRIVATE KEY BLOCK]',
    advice: 'Revoke and rotate this key immediately; it grants direct access.',
  },
  {
    id: 'gcp-service-account', name: 'GCP service-account key', severity: 'critical',
    re: /-----BEGIN PRIVATE KEY-----[\s\S]{0,4000}?\.iam\.gserviceaccount\.com/g,
    mask: () => '[GCP SERVICE ACCOUNT KEY]',
    advice: 'Delete this service-account key in IAM and generate a fresh one; it grants API access.',
  },
  {
    // AKIA long-term, ASIA STS, ABIA STS bearer, ACCA context credential. AIDA/AROA/
    // AGPA/ANPA/ANVA are user/role/group/policy ids, not credentials, so they are out.
    id: 'aws-key', name: 'AWS access key ID', severity: 'high',
    re: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
    advice: 'Deactivate the access key ID in IAM and rotate its secret.',
  },
  {
    id: 'aws-secret', name: 'AWS secret access key', severity: 'critical',
    re: new RegExp(String.raw`(?:aws_?)?(?:secret_?(?:access_?)?|access_?)key["'\s:=]{1,12}([A-Za-z0-9/+]{40})` + END, 'gi'),
    g: 1,
    validate: (m) => shannonEntropy(m) >= 4.0,
    advice: 'Rotate the AWS secret key and audit CloudTrail for misuse.',
  },
  {
    id: 'gcp-key', name: 'Google API key', severity: 'high',
    re: /(?<![0-9A-Za-z_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g,
    advice: 'Restrict or regenerate the Google API key in the Cloud console.',
  },
  {
    id: 'google-oauth', name: 'Google OAuth client secret', severity: 'high',
    re: /\bGOCSPX-[A-Za-z0-9_-]{20,}/g,
    advice: 'Rotate the OAuth client secret in the Cloud console.',
  },
  {
    id: 'google-oauth-client-id', name: 'Google OAuth client ID', severity: 'low',
    re: /\b\d+-[a-z0-9]+\.apps\.googleusercontent\.com\b/g,
    advice: 'Client IDs are semi-public; make sure the matching client secret is not exposed.',
  },
  {
    // Classic tokens are the prefix plus exactly 36 characters.
    id: 'github-token', name: 'GitHub token', severity: 'critical',
    re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/g,
    advice: 'Revoke the GitHub token in developer settings now.',
  },
  {
    // Fine-grained: github_pat_ + 22 + "_" + 59 (82 after the prefix).
    id: 'github-pat-fine', name: 'GitHub fine-grained token', severity: 'critical',
    re: /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b/g,
    advice: 'Revoke this fine-grained personal access token immediately.',
  },
  {
    id: 'gitlab-pat', name: 'GitLab personal access token', severity: 'critical',
    re: /\bglpat-[A-Za-z0-9_-]{20,}/g,
    advice: 'Revoke the GitLab token under User Settings → Access Tokens.',
  },
  {
    id: 'slack-token', name: 'Slack token', severity: 'high',
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,
    advice: 'Revoke the Slack token in the app management console.',
  },
  {
    id: 'slack-app-token', name: 'Slack app-level token', severity: 'high',
    re: /\bxapp-\d-[A-Za-z0-9]+-\d+-[a-z0-9]+\b/gi,
    advice: 'Revoke the Slack app-level token in the app management console.',
  },
  {
    id: 'slack-webhook', name: 'Slack webhook URL', severity: 'medium',
    re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/g,
    advice: 'Regenerate the incoming webhook; anyone with the URL can post.',
  },
  {
    id: 'stripe-key', name: 'Stripe live key', severity: 'critical',
    re: /\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b/g,
    advice: 'Roll the Stripe live key in the dashboard immediately.',
  },
  {
    id: 'stripe-test-key', name: 'Stripe test secret key', severity: 'medium',
    re: /\bsk_test_[A-Za-z0-9]{24,}\b/g,
    advice: 'Test keys reach your Stripe test data; rotate it and keep it out of source.',
  },
  {
    id: 'stripe-publishable-key', name: 'Stripe publishable key', severity: 'low',
    re: /\bpk_live_[A-Za-z0-9]{24,}\b/g,
    advice: 'Publishable keys are meant to be public; confirm it is not a secret key.',
  },
  {
    // sk-, sk-proj-, sk-svcacct-, sk-admin-; never the Anthropic sk-ant- prefix.
    id: 'openai-key', name: 'OpenAI API key', severity: 'high',
    re: /\bsk-(?!ant-)(?:(?:proj|svcacct|admin)-)?[A-Za-z0-9_-]{40,}/g,
    validate: (m) => shannonEntropy(m) >= 3.5,
    advice: 'Revoke the OpenAI key in the API dashboard.',
  },
  {
    id: 'anthropic-key', name: 'Anthropic API key', severity: 'high',
    re: /\bsk-ant-[A-Za-z0-9_-]{40,}/g,
    advice: 'Revoke the Anthropic key in the console.',
  },
  {
    id: 'jwt', name: 'JSON Web Token', severity: 'medium',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    advice: 'Treat the JWT as a live credential until it expires; do not share it.',
  },
  {
    id: 'twilio-account-sid', name: 'Twilio account SID', severity: 'medium',
    re: /\bAC[a-f0-9]{32}\b/g,
    advice: 'Pair with the auth token; rotate the Twilio auth token if exposed.',
  },
  {
    id: 'twilio-api-key', name: 'Twilio API key', severity: 'high',
    re: /\bSK[0-9a-f]{32}\b/g,
    advice: 'Delete the API key in the Twilio console and load a new one from the environment.',
  },
  {
    id: 'twilio-auth-token', name: 'Twilio auth token', severity: 'critical',
    re: /(?:twilio[\w.-]{0,30}?token|auth_token)["']?\s*[=:]\s*["']?([a-f0-9]{32})\b/gi,
    g: 1,
    advice: 'Rotate the Twilio auth token; it can send SMS and place calls.',
  },
  {
    id: 'sendgrid-key', name: 'SendGrid API key', severity: 'high',
    re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g,
    advice: 'Delete and recreate the SendGrid key.',
  },
  {
    id: 'mailgun-key', name: 'Mailgun API key', severity: 'high',
    re: /\bkey-[0-9a-f]{32}\b/gi,
    advice: 'Rotate the Mailgun API key in the control panel.',
  },
  {
    id: 'npm-token', name: 'npm access token', severity: 'high',
    re: /\bnpm_[A-Za-z0-9]{36}\b/g,
    advice: 'Revoke the npm token with `npm token revoke` or in your npm account.',
  },
  {
    id: 'huggingface-token', name: 'Hugging Face access token', severity: 'high',
    re: /\bhf_[A-Za-z0-9]{34,}\b/g,
    advice: 'Revoke the token in your Hugging Face settings (Access Tokens) and create a new one.',
  },
  {
    // Real PyPI tokens are macaroons whose base64 always starts "AgE".
    id: 'pypi-token', name: 'PyPI API token', severity: 'high',
    re: /\bpypi-AgE[A-Za-z0-9_-]{50,}/g,
    advice: 'Revoke the token in your PyPI account settings.',
  },
  {
    // Group 1: the password (Code Scanner masks just that); the whole match is the URL.
    id: 'conn-string', name: 'Database connection string', severity: 'critical',
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/"']+:([^\s@/"']+)@[^\s/"']+/gi,
    mask: (m) => m.replace(/:\/\/([^:]+):[^@]+@/, '://$1:••••••@'),
    advice: 'Embedded DB credentials are exposed; rotate and use a secrets store.',
  },
  {
    id: 'azure-storage-key', name: 'Azure Storage account key', severity: 'critical',
    re: /AccountKey=([A-Za-z0-9+/]{86}==)/g,
    g: 1,
    advice: 'Rotate the storage account key in the Azure portal; it grants full access.',
  },
  {
    id: 'azure-sas', name: 'Azure SAS token', severity: 'high',
    re: /[?&]sv=\d{4}-\d{2}-\d{2}&[^\s"'<>]*?sig=[A-Za-z0-9%]{10,}/gi,
    mask: () => '[AZURE SAS TOKEN]',
    advice: 'Revoke the shared access signature; anyone with the URL has the granted access.',
  },
  {
    // The current "xxxNQ~..." format anywhere, or an older secret assigned to an Azure client-secret name.
    id: 'azure-ad-secret', name: 'Azure AD client secret', severity: 'critical',
    re: /\b([A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34})\b|(?:AZURE_CLIENT_SECRET|azure[\w.-]{0,20}?client[_-]?secret)["']?\s*[=:]\s*["']?([A-Za-z0-9_.~-]{34,})/gi,
    g: [1, 2],
    advice: 'Rotate the app registration client secret in Entra ID / Azure AD.',
  },
  {
    id: 'heroku-key', name: 'Heroku API key', severity: 'high',
    re: /\bheroku[^\n]{0,40}?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/gi,
    g: 1,
    advice: 'Regenerate the Heroku API key with `heroku authorizations:rotate`.',
  },
  {
    id: 'digitalocean-token', name: 'DigitalOcean token', severity: 'critical',
    re: /\bdo[opr]_v1_[a-f0-9]{64}\b/g,
    advice: 'Revoke the DigitalOcean token in the API section of the control panel.',
  },
  {
    id: 'planetscale-token', name: 'PlanetScale token', severity: 'critical',
    re: /\bpscale_(?:tkn|pw|oauth)_[A-Za-z0-9._-]{32,}/g,
    advice: 'Revoke the PlanetScale password/token in the database settings.',
  },
  {
    id: 'discord-bot-token', name: 'Discord bot token', severity: 'high',
    re: /\b[MNO][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/g,
    advice: 'Reset the bot token in the Discord developer portal.',
  },
  {
    id: 'telegram-bot-token', name: 'Telegram bot token', severity: 'high',
    re: /(?<![\d])\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g,
    advice: 'Revoke the token with @BotFather (/revoke).',
  },
  {
    // Datadog API keys are 32 hex, application keys 40 hex; neither has a prefix, so a key name is required.
    id: 'datadog-key', name: 'Datadog API key', severity: 'medium',
    re: /(?:datadog|\bdd)[_-]?(?:api|app(?:lication)?)[_-]?key["']?\s*[=:]\s*["']?([a-f0-9]{40}|[a-f0-9]{32})\b/gi,
    g: 1,
    advice: 'Revoke the key in Datadog Organization Settings → API / Application Keys.',
  },
  {
    id: 'shopify-token', name: 'Shopify access token', severity: 'high',
    re: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g,
    advice: 'Uninstall/rotate the app credential in the Shopify admin.',
  },
  {
    id: 'cloudflare-global-key', name: 'Cloudflare global API key', severity: 'high',
    re: /(?:CF_API_KEY|cloudflare[\w.-]{0,20}?key)["']?\s*[=:]\s*["']?([a-f0-9]{37})\b/gi,
    g: 1,
    advice: 'Roll the Global API Key in the Cloudflare dashboard; prefer scoped API tokens.',
  },
  {
    // Scoped API tokens have no prefix: only a Cloudflare variable name identifies them.
    id: 'cloudflare-api-token', name: 'Cloudflare API token', severity: 'medium',
    re: /(?:CF_API_TOKEN|cloudflare[\w.-]{0,20}?token)["']?\s*[=:]\s*["']?([A-Za-z0-9_-]{40})(?![A-Za-z0-9_-])/gi,
    g: 1,
    advice: 'Roll the API token in the Cloudflare dashboard.',
  },
  {
    id: 'bearer-auth', name: 'Bearer / Authorization token', severity: 'high',
    re: /\b(?:Authorization:\s*)?(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{16,})/g,
    g: 1,
    validate: (m) => !/^(?:your|example|placeholder|token|changeme|xxx|redacted)/i.test(m) && !/^(.)\1+$/.test(m),
    advice: 'Treat this header credential as live; rotate it and do not log Authorization headers.',
  },
  {
    // `name = "value"` where the name holds a credential word. Group 1 is the key name
    // (consumers decide how strictly it must match SECRET_KEY_WORDS), group 2 the value.
    id: 'pat-assignment', name: 'Password or secret in assignment', severity: 'high',
    re: /(?<![A-Za-z0-9])([A-Za-z0-9_.-]*?(?:passw(?:or)?d|pwd|secret|token|api[_-]?key|apikey|access[_-]?(?:key|token)|auth[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*)["']?[\t ]*[:=][\t ]*["']([^"'\s]{6,})["']/gi,
    g: 2,
    validate: realValue,
    advice: 'Move the secret to a secrets manager or environment variable.',
  },
];

// The whole PEM block, BEGIN..END, for consumers that redact the full key.
export const PRIVATE_KEY_BLOCK_RE = new RegExp(`-----BEGIN (${PEM_TYPES})PRIVATE KEY(?: BLOCK)?-----[\\s\\S]*?-----END \\1PRIVATE KEY(?: BLOCK)?-----`, 'g');

export const DETECTOR_BY_ID = Object.freeze(Object.fromEntries(SECRET_DETECTORS.map((d) => [d.id, d])));

/** The detector with this id; throws on an unknown id so an adapter typo fails loudly. */
export function detector(id) {
  const d = DETECTOR_BY_ID[id];
  if (!d) throw new Error('unknown secret detector: ' + id);
  return d;
}

/** The secret value of a regex match for detector `d` (its capture group, else the whole match). */
export function valueOf(d, m) {
  if (d.g == null) return m[0];
  for (const g of [].concat(d.g)) if (m[g] != null) return m[g];
  return undefined;
}

/**
 * Every hit of detector `d` (or a regex override) in `text`:
 * [{ value, start, end, whole, index, m }] where start/end locate the value and
 * index is the start of the whole match. `opts.validate` (default true) applies d.validate.
 */
export function findAll(d, text, opts = {}) {
  const s = String(text == null ? '' : text);
  const re = opts.re || d.re;
  const out = [];
  re.lastIndex = 0; // matchAll starts its private copy at the shared regex's lastIndex
  for (const m of s.matchAll(re)) {
    const whole = m[0];
    const value = valueOf(d, m);
    if (!value) continue;
    const off = value === whole ? 0 : whole.indexOf(value);
    const start = m.index + (off < 0 ? 0 : off);
    if (opts.validate !== false && d.validate && !d.validate(value, whole, { ...(opts.ctx || {}), text: s, index: start })) continue;
    out.push({ value, start, end: start + value.length, whole, index: m.index, m });
  }
  return out;
}

/** First validated hit of `d` in `text` that also passes `accept(hit)`, or null. */
export function findFirst(d, text, accept) {
  for (const h of findAll(d, text)) if (!accept || accept(h)) return h;
  return null;
}
