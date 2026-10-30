// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Code Scanner — deterministic detection rules (pure, DOM-free, no network).
//
// Every rule here is original, written from the CWE definitions. Nothing is copied
// from third-party rule registries. scanFile(path, text) returns findings with exact
// line/column positions so the viewer can jump straight to the vulnerable code, and
// parseManifest(path, text) extracts pinned dependencies (with their declaring line)
// for the OSV.dev lookup. No AI is involved in detection or ranking.

import { taintScan } from "./taint-js.js?v=20261013a";
import { detector, findAll, keyHoldsSecret, assignmentKey } from "../core/secret-detectors.js";
import { OSV_ECOSYSTEM, formatForName, parseLockfile } from "../core/lockfiles.js";

export const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ── Language detection ─────────────────────────────────────────────────────────
const EXT_LANG = {
  js: "js", mjs: "js", cjs: "js", jsx: "js", ts: "js", tsx: "js", vue: "js", svelte: "js",
  py: "py", go: "go", php: "php", java: "java", kt: "java", rb: "rb", cs: "cs",
  yml: "yaml", yaml: "yaml", tf: "tf", sh: "sh", env: "env"
};
export function langOf(path) {
  const p = String(path || "");
  const base = p.split("/").pop();
  if (/^Dockerfile(\..+)?$/i.test(base) || /\.dockerfile$/i.test(base)) return "docker";
  if (/^\.env(\..+)?$/i.test(base)) return "env";
  if (/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(p)) return "gha";
  const ext = (base.includes(".") ? base.split(".").pop() : "").toLowerCase();
  // hasOwnProperty guard: `ext` is derived from a scanned filename, so a path like "x.constructor"
  // would otherwise resolve to the inherited Object.prototype.constructor (a truthy function) and
  // be returned instead of "".
  return Object.prototype.hasOwnProperty.call(EXT_LANG, ext) ? EXT_LANG[ext] : "";
}

// ── Helpers ────────────────────────────────────────────────────────────────────
export function entropy(s) {
  const m = new Map();
  for (const c of s) m.set(c, (m.get(c) || 0) + 1);
  let e = 0;
  for (const n of m.values()) { const p = n / s.length; e -= p * Math.log2(p); }
  return e;
}
export function mask(s) {
  const v = String(s || "");
  return v.length <= 10 ? v.slice(0, 2) + "…" : v.slice(0, 4) + "…" + v.slice(-4);
}
const PLACEHOLDER = /(example|sample|dummy|placeholder|changeme|change_me|your[_-]?|xxxx|\*\*\*\*|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|process\.env|os\.environ|getenv|redacted|test[_-]?key|fake|1234567890|0123456789|abcdefghij|SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c|GEZDGNBVGY3TQOJQ)/i; // public samples: the jwt.io token, the RFC 4226 test secret
const PLACEHOLDER_PASS = /^(?:pass(?:word)?|secret|pwd|root|admin|user|test|changeme|\*+|x+)$/i; // user:pass@host in docs and examples
const KEY_BODY = /[A-Za-z0-9+/=]{40,}|\\n[A-Za-z0-9+/]{20,}/; // a real key block carries base64 material
const TESTY_PATH = /(^|\/)(tests?|__tests__|spec|specs|fixtures?|examples?|samples?|docs?|mocks?)(\/|$)|\.(md|rst|example|sample|template|dist)$|\.(test|spec)\.[a-z]+$/i;
const SKIP_LINE = 2000; // ignore pathological minified lines (regex cost + noise)

// ── Secret rules (all text files) ──────────────────────────────────────────────
// What each secret looks like comes from the shared catalogue (core/secret-detectors.js);
// a rule names its detectors and adds the Code Scanner's own ids, severity, CWE and
// advice. `pick` chooses the value to report (masked in the UI, never sent anywhere),
// `accept` / `minLen` / `minEntropy` filter dictionary-looking matches.
// Files whose unquoted `name = value` lines are literal values, not code.
const CONFIG_FILE = /(?:^|\/)\.env(?:\.[^/]*)?$|\.(?:ya?ml|properties|ini|cfg|conf|env)$/i;
export const SECRET_RULES = [
  { id: "secret.aws-access-key", title: "AWS access key ID", detectors: ["aws-key"], sev: "high", cwe: 798,
    why: "An AWS access key ID in source usually travels with its secret key and grants API access to the account.",
    fix: "Revoke the key in IAM, load credentials from the environment or an IAM role, and purge it from git history." },
  { id: "secret.aws-secret-key", title: "AWS secret access key", detectors: ["aws-secret"], sev: "critical", cwe: 798, minEntropy: 3.8,
    why: "The AWS secret access key signs API requests; with the key ID it is full account access at that identity's privileges.",
    fix: "Rotate the key pair immediately, use IAM roles or a secrets manager, and purge it from git history." },
  { id: "secret.github-token", title: "GitHub token", detectors: ["github-token", "github-pat-fine"], sev: "critical", cwe: 798,
    why: "GitHub tokens authenticate as a user or app and can read or push to repositories.",
    fix: "Revoke it at github.com/settings/tokens, then store tokens in Actions secrets or a secrets manager." },
  { id: "secret.slack-token", title: "Slack token", detectors: ["slack-token"], sev: "high", cwe: 798,
    why: "Slack tokens can read channels and post messages as the workspace app or user.",
    fix: "Revoke the token in the Slack app settings and load it from the environment." },
  { id: "secret.slack-webhook", title: "Slack incoming webhook", detectors: ["slack-webhook"], sev: "medium", cwe: 798,
    why: "Anyone with the webhook URL can post messages into the channel, which enables convincing phishing.",
    fix: "Regenerate the webhook and keep the URL in configuration, not code." },
  { id: "secret.stripe-live", title: "Stripe live secret key", detectors: ["stripe-key"], sev: "critical", cwe: 798,
    why: "A live Stripe secret key can create charges, refunds and read customer payment data.",
    fix: "Roll the key in the Stripe dashboard and load it from the server environment only." },
  { id: "secret.google-api-key", title: "Google API key", detectors: ["gcp-key"], sev: "low", cwe: 798,
    why: "Google API keys are billable. Firebase web keys are designed to be public, but other keys (Maps, Gemini, Cloud) are not.",
    fix: "If this is not a public Firebase config key, restrict or rotate it in Google Cloud Console and move it server-side." },
  { id: "secret.private-key", title: "Private key block", detectors: ["private-key"], sev: "critical", cwe: 321,
    why: "A committed private key lets anyone impersonate the server, sign code, or decrypt traffic.",
    fix: "Treat the key as compromised: reissue it, remove the file, and purge it from git history." },
  { id: "secret.openai-key", title: "OpenAI API key", detectors: ["openai-key"], sev: "high", cwe: 798, minEntropy: 4,
    why: "OpenAI keys are billed to the owner and can be abused for paid usage.",
    fix: "Revoke the key in the OpenAI dashboard and call the API from a server that reads it from the environment." },
  { id: "secret.anthropic-key", title: "Anthropic API key", detectors: ["anthropic-key"], sev: "high", cwe: 798,
    why: "Anthropic keys are billed to the owner and can be abused for paid usage.",
    fix: "Revoke the key in the Anthropic Console and keep it server-side." },
  { id: "secret.sendgrid-key", title: "SendGrid API key", detectors: ["sendgrid-key"], sev: "high", cwe: 798,
    why: "A SendGrid key can send email as your domain, which passes SPF/DKIM checks.",
    fix: "Delete the key in SendGrid and load a new one from the environment." },
  { id: "secret.twilio-key", title: "Twilio API key", detectors: ["twilio-api-key"], sev: "high", cwe: 798,
    why: "Twilio API keys can send SMS and place calls billed to the account.",
    fix: "Delete the key in the Twilio console and load a new one from the environment." },
  { id: "secret.npm-token", title: "npm access token", detectors: ["npm-token"], sev: "critical", cwe: 798,
    why: "An npm token can publish packages under your account, which is a supply-chain compromise.",
    fix: "Revoke it with `npm token revoke` and use granular, CI-scoped tokens from secrets." },
  { id: "secret.gitlab-token", title: "GitLab personal access token", detectors: ["gitlab-pat"], sev: "critical", cwe: 798,
    why: "A GitLab token authenticates as its user and can read or push to repositories and run pipelines.",
    fix: "Revoke it under GitLab User Settings > Access Tokens and keep tokens in CI/CD variables." },
  { id: "secret.stripe-test", title: "Stripe test secret key", detectors: ["stripe-test-key"], sev: "medium", cwe: 798,
    why: "A test-mode key works against the account's test data and webhooks, and live keys are often stored beside it.",
    fix: "Roll the key in the Stripe dashboard and load it from the server environment." },
  { id: "secret.huggingface-token", title: "Hugging Face access token", detectors: ["huggingface-token"], sev: "high", cwe: 798,
    why: "A Hugging Face token can read private models and datasets and, with write scope, replace them.",
    fix: "Revoke it at huggingface.co/settings/tokens and load it from the environment." },
  { id: "secret.pypi-token", title: "PyPI upload token", detectors: ["pypi-token"], sev: "critical", cwe: 798,
    why: "A PyPI token can upload new releases of your packages, which is a supply-chain compromise.",
    fix: "Delete the token on pypi.org and publish through trusted publishing or a CI secret." },
  { id: "secret.digitalocean-token", title: "DigitalOcean token", detectors: ["digitalocean-token"], sev: "critical", cwe: 798,
    why: "A DigitalOcean token can create, read and destroy droplets, databases and storage on the account.",
    fix: "Revoke it in the DigitalOcean control panel under API and load a new one from the environment." },
  { id: "secret.planetscale-token", title: "PlanetScale token or password", detectors: ["planetscale-token"], sev: "critical", cwe: 798,
    why: "PlanetScale tokens and passwords give access to the database branches they are scoped to.",
    fix: "Revoke it in PlanetScale and load credentials from the environment." },
  { id: "secret.shopify-token", title: "Shopify access token", detectors: ["shopify-token"], sev: "high", cwe: 798,
    why: "A Shopify access token acts on the store's orders, customers and products within its scopes.",
    fix: "Rotate it in the Shopify admin (uninstall and reinstall a custom app) and keep it server-side." },
  { id: "secret.google-oauth-secret", title: "Google OAuth client secret", detectors: ["google-oauth"], sev: "high", cwe: 798,
    why: "With the client secret anyone can run the OAuth flow as your app and exchange codes for tokens.",
    fix: "Reset the secret in Google Cloud Console > Credentials and keep it server-side." },
  { id: "secret.azure-storage-key", title: "Azure Storage account key", detectors: ["azure-storage-key"], pick: (h) => h.m[1], sev: "critical", cwe: 798,
    why: "An account key is full read, write and delete access to every container, queue and table in the storage account.",
    fix: "Rotate the key in the Azure portal and use managed identities or short-lived SAS tokens." },
  { id: "secret.jwt", title: "Hardcoded JSON Web Token", detectors: ["jwt"], sev: "medium", cwe: 798,
    why: "A committed JWT may still be valid and grant the session or service access it encodes.",
    fix: "Remove the token; if it is long-lived, rotate the signing key so it stops verifying." },
  { id: "secret.db-url", title: "Database URL with password", detectors: ["conn-string"], pick: (h) => h.m[1], minLen: 4, sev: "high", cwe: 798,
    why: "Connection strings with an inline password give direct database access to anyone who reads the repo.",
    fix: "Move the connection string to an environment variable or secrets manager and rotate the password." },
  { id: "secret.generic", title: "Hardcoded credential", detectors: ["pat-assignment", "config-assignment"], only: { "config-assignment": CONFIG_FILE }, accept: (h) => keyHoldsSecret(h.m[1] || assignmentKey(h.whole), "._-"), minLen: 12, sev: "medium", cwe: 798, minEntropy: 3.5,
    why: "Credentials embedded in source are readable by everyone with repo access and persist in git history.",
    fix: "Load the value from the environment or a secrets manager, rotate it, and purge it from history." }
];

// First hit of a secret rule in `text`: { val, index } (index = start of the match), or null.
function secretHit(rule, text, path = "") {
  let sample = null; // a match the detector rejected as an example/placeholder value
  for (const id of rule.detectors) {
    if (rule.only?.[id] && !rule.only[id].test(path)) continue;
    const d = detector(id);
    for (const h of findAll(d, text, { validate: false })) { // validated here so placeholder rejects can be reported
      if (d.validate && !d.validate(h.value, h.whole, { text, index: h.start })) { if (PLACEHOLDER.test(h.value)) sample = h.value; continue; }
      if (rule.accept && !rule.accept(h)) continue;
      const val = rule.pick ? rule.pick(h) : h.value;
      if (!val || (rule.minLen && val.length < rule.minLen)) continue;
      return { val, index: h.index };
    }
  }
  return sample ? { placeholder: sample } : null;
}

// ── Code rules (per language) ──────────────────────────────────────────────────
// `re` must match the (comment-stripped) line. `near` (optional) must match within
// ±`win` lines for the rule to fire; `unless` (optional) suppresses the hit when it
// matches the line or the window.
const R = (o) => ({ win: 4, ...o });
export const CODE_RULES = [
  // JavaScript / TypeScript
  R({ id: "js.eval", langs: ["js"], title: "Dynamic code evaluation", sev: "high", cwe: 95,
    re: /\b(?:eval|new\s+Function)\s*\(\s*(?!["'`][^"'`]*["'`]\s*\))[^)\s]/,
    why: "eval/new Function run arbitrary strings as code; any attacker influence on the argument is code execution.",
    fix: "Use JSON.parse for data, or a lookup table / explicit dispatch instead of building code from strings." }),
  R({ id: "js.child-process-exec", langs: ["js"], title: "Shell command built from variables", sev: "critical", cwe: 78,
    // The lookbehind drops RegExp.prototype.exec: a regex literal (/x/g.exec) or a receiver
    // named like a pattern (re, rx, regex, pattern, matcher, urlRe, URL_RE, tokenPattern).
    re: /(?<!(?:\/[dgimsuyv]*|(?<![\w$])(?:re|RE|Re|rx|RX|regex|Regex|REGEX|regexp|RegExp|pattern|Pattern|PATTERN|pat|matcher)|[A-Za-z0-9$](?:Re|RE|Rx|RX|Regex|REGEX|RegExp|Regexp|Pattern|PATTERN)|_(?:re|RE|rx|RX|regex|REGEX|pattern|PATTERN))\s*\.\s*)\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+|[A-Za-z_$][\w$.]*\s*[+,)])/,
    near: /child_process|require\(["']child_process["']\)|from\s+["'](?:node:)?child_process["']|\bshelljs\b/,
    win: 400,
    why: "exec() hands the whole string to a shell, so metacharacters in interpolated values run extra commands.",
    fix: "Use execFile()/spawn() with an argument array (no shell) and validate inputs against an allowlist." }),
  R({ id: "js.inner-html", langs: ["js"], title: "Unsanitised HTML sink", sev: "high", cwe: 79,
    re: /\.(?:innerHTML|outerHTML)\s*\+?=(?!=)(?!\s*["'`][^"'`$]*["'`]\s*;?\s*$)|\.insertAdjacentHTML\s*\(\s*["'][^"']+["']\s*,(?!\s*["'`][^"'`$]*["'`]\s*\))/,
    unless: /DOMPurify\.sanitize|sanitizeHtml|\besc(?:ape)?(?:Html)?\s*\(/,
    why: "Assigning dynamic strings to innerHTML parses them as markup; attacker-controlled text becomes script (XSS).",
    fix: "Use textContent for text, build nodes with DOM APIs, or sanitise with DOMPurify before inserting HTML." }),
  R({ id: "js.document-write", langs: ["js"], title: "document.write with dynamic content", sev: "medium", cwe: 79,
    re: /\bdocument\.write(?:ln)?\s*\((?!\s*["'`][^"'`$]*["'`]\s*\))/,
    why: "document.write parses its argument as HTML, an XSS sink when the content is not constant.",
    fix: "Create elements with DOM APIs and set textContent instead." }),
  R({ id: "js.dangerously-set-html", langs: ["js"], title: "React dangerouslySetInnerHTML", sev: "medium", cwe: 79,
    re: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:/, unless: /DOMPurify|sanitize/i,
    why: "React escapes output by default; this prop opts out and renders raw HTML.",
    fix: "Sanitise the HTML (e.g. DOMPurify.sanitize) or render the content as text." }),
  R({ id: "js.sql-concat", langs: ["js"], title: "SQL query built with string concatenation", sev: "high", cwe: 89,
    re: /\.(?:query|execute|raw|exec)\s*\(\s*(?:`\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b[^`]*\$\{|"\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b[^"]*"\s*\+|'\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b[^']*'\s*\+)/i,
    why: "Values concatenated into SQL can change the query's structure (SQL injection).",
    fix: "Use parameterised queries / placeholders (e.g. query('... WHERE id = $1', [id]))." }),
  R({ id: "js.tls-disabled", langs: ["js"], title: "TLS certificate verification disabled", sev: "high", cwe: 295,
    re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED["']?\]?\s*=\s*["']?0/,
    why: "Without certificate checks any network attacker can intercept and modify HTTPS traffic.",
    fix: "Remove the override; if a private CA is needed, pass it via the `ca` option." }),
  R({ id: "js.cors-wildcard-credentials", langs: ["js"], title: "Permissive CORS with credentials", sev: "medium", cwe: 942,
    re: /origin\s*:\s*(?:true|["']\*["'])|Access-Control-Allow-Origin["']\s*,\s*(?:req\.headers\.origin|["']\*["'])/,
    near: /credentials\s*:\s*true|Allow-Credentials["']\s*,\s*["']?true/, win: 8,
    why: "Reflecting any origin while allowing credentials lets any website make authenticated requests as the user.",
    fix: "Allow only an explicit list of trusted origins when credentials are enabled." }),
  R({ id: "js.jwt-hardcoded-secret", langs: ["js"], title: "JWT signed with a hardcoded secret", sev: "high", cwe: 798,
    re: /\bjwt\.(?:sign|verify)\s*\([^)]*,\s*["'`][^"'`]{4,}["'`]/,
    why: "Anyone who reads the secret can mint valid tokens for any user.",
    fix: "Load the signing key from the environment or a KMS and rotate the current one." }),
  R({ id: "js.jwt-none", langs: ["js", "py", "java", "go"], title: "JWT 'none' algorithm accepted", sev: "high", cwe: 347,
    re: /algorithms\s*[:=]\s*\[[^\]\n]*["']none["']|UnsafeAllowNoneSignatureType/i, // darknode-ignore: this is the detector. Fires on the verify allowlist; a decoder showing alg "none" is not acceptance
    why: "Accepting alg=none means tokens are trusted without any signature.",
    fix: "Pin the expected algorithm (e.g. ['RS256']) and never allow 'none'." }),
  R({ id: "js.weak-hash-password", langs: ["js"], title: "Weak hash used for passwords", sev: "medium", cwe: 916,
    re: /createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/i, near: /passw|pwd/i,
    why: "MD5/SHA-1 are fast hashes; stolen password hashes are cracked at billions of guesses per second.",
    fix: "Use bcrypt, scrypt or Argon2 with a per-user salt." }),
  R({ id: "js.insecure-random", langs: ["js"], title: "Math.random used for a security value", sev: "medium", cwe: 338,
    re: /Math\.random\s*\(/, near: /\b(?:token|secret|nonce|salt|password|otp|session|apikey|api_key)\b/i, win: 2,
    unless: /Math\.floor\s*\(\s*Math\.random\s*\(\s*\)\s*\*\s*\d{1,3}\s*\)/, // a pick from at most 999 values (a game, a delay) is not a secret
    why: "Math.random is predictable; values derived from it can be guessed.",
    fix: "Use crypto.randomUUID() or crypto.getRandomValues()/randomBytes()." }),
  R({ id: "js.open-redirect", langs: ["js"], title: "Redirect to a user-supplied URL", sev: "medium", cwe: 601,
    re: /\.redirect\s*\(\s*(?:\d{3}\s*,\s*)?req\.(?:query|body|params)\b/,
    why: "Redirecting to request parameters lets attackers bounce victims through your domain to phishing pages.",
    fix: "Redirect only to relative paths or an allowlist of destinations." }),
  R({ id: "js.path-traversal", langs: ["js"], title: "File path built from request input", sev: "high", cwe: 22,
    re: /\b(?:readFile|readFileSync|createReadStream|sendFile|unlink|writeFile|writeFileSync)\s*\([^)]*req\.(?:query|body|params)\b|path\.(?:join|resolve)\s*\([^)]*req\.(?:query|body|params)\b/,
    why: "Values like ../../etc/passwd escape the intended directory.",
    fix: "Resolve the path, then verify it starts with the allowed base directory; reject anything else." }),
  R({ id: "js.postmessage-wildcard", langs: ["js"], title: "postMessage to any origin", sev: "medium", cwe: 345,
    re: /\.postMessage\s*\([^)]*,\s*["']\*["']\s*\)/,
    why: "Sending with targetOrigin '*' delivers the data to whatever page is in that window, including attacker pages.",
    fix: "Pass the exact expected origin as targetOrigin." }),
  // Python
  R({ id: "py.yaml-load", langs: ["py"], title: "yaml.load without a safe loader", sev: "high", cwe: 502,
    re: /\byaml\.(?:load|load_all)\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe|Base)Loader)/,
    why: "The full YAML loader can construct arbitrary Python objects, leading to code execution.",
    fix: "Use yaml.safe_load() (or Loader=yaml.SafeLoader)." }),
  R({ id: "py.pickle", langs: ["py"], title: "Deserialising with pickle/marshal", sev: "high", cwe: 502,
    re: /\b(?:pickle|cPickle|dill|marshal)\.loads?\s*\(|\bshelve\.open\s*\(/,
    why: "Unpickling attacker-controlled data executes arbitrary code by design.",
    fix: "Use JSON or another data-only format; if pickle is unavoidable, sign and verify the payload first." }),
  R({ id: "py.shell-true", langs: ["py"], title: "Command run through the shell", sev: "high", cwe: 78,
    re: /\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True|\bos\.(?:system|popen)\s*\((?!\s*["'][^"']*["']\s*\))/,
    why: "Passing a string to the shell lets metacharacters in any interpolated value run extra commands.",
    fix: "Call subprocess.run([...args], shell=False) with an argument list." }),
  R({ id: "py.sql-format", langs: ["py"], title: "SQL query built with string formatting", sev: "high", cwe: 89,
    re: /\.execute(?:many)?\s*\(\s*(?:f["']|(?:"[^"]*(?:SELECT|INSERT|UPDATE|DELETE)[^"]*"|'[^']*(?:SELECT|INSERT|UPDATE|DELETE)[^']*')\s*(?:%|\.format\s*\(|\+))/i,
    why: "Formatting values into SQL text allows SQL injection.",
    fix: "Pass parameters separately: cursor.execute('... WHERE id = %s', (id,))." }),
  R({ id: "py.tls-disabled", langs: ["py"], title: "TLS certificate verification disabled", sev: "high", cwe: 295,
    re: /\bverify\s*=\s*False\b|ssl\._create_unverified_context|CERT_NONE/,
    why: "Disabling verification exposes requests to interception and tampering.",
    fix: "Remove verify=False; point `verify` at a CA bundle if you use a private CA." }),
  R({ id: "py.weak-hash-password", langs: ["py"], title: "Weak hash used for passwords", sev: "medium", cwe: 916,
    re: /\bhashlib\.(?:md5|sha1)\s*\(/, near: /passw|pwd/i,
    why: "Fast hashes make stolen password hashes cheap to crack.",
    fix: "Use argon2-cffi, bcrypt or hashlib.scrypt with a salt." }),
  R({ id: "py.debug-on", langs: ["py"], title: "Debug mode enabled", sev: "medium", cwe: 489,
    re: /^\s*DEBUG\s*=\s*True\b|\.run\s*\([^)]*debug\s*=\s*True/,
    unless: /settings\/(?:dev|local|test)|_dev\.py|_local\.py/,
    why: "Debug mode exposes stack traces, settings and (in Flask/Werkzeug) an interactive console.",
    fix: "Drive debug from the environment and keep it off in production." }),
  R({ id: "py.eval", langs: ["py"], title: "Dynamic code evaluation", sev: "high", cwe: 95,
    re: /(?<![\w.])(?:eval|exec)\s*\(\s*(?!["'][^"']*["']\s*\))[^)\s]/,
    why: "eval/exec run arbitrary code from strings.",
    fix: "Use ast.literal_eval for literals, or explicit parsing/dispatch." }),
  // Go
  R({ id: "go.tls-skip-verify", langs: ["go"], title: "TLS verification disabled", sev: "high", cwe: 295,
    re: /InsecureSkipVerify\s*:\s*true/,
    why: "The client accepts any certificate, so traffic can be intercepted.",
    fix: "Remove InsecureSkipVerify; add a private CA to RootCAs if needed." }),
  R({ id: "go.sql-sprintf", langs: ["go"], title: "SQL query built with Sprintf or concatenation", sev: "high", cwe: 89,
    re: /\.(?:Query|QueryRow|Exec|QueryContext|ExecContext)\s*\(\s*(?:ctx\s*,\s*)?fmt\.Sprintf\s*\(|fmt\.Sprintf\s*\(\s*"(?:SELECT|INSERT|UPDATE|DELETE)\b[^"]*%[sv]|\.(?:Query|QueryRow|Exec|QueryContext|ExecContext)\s*\(\s*(?:ctx\s*,\s*)?"\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b[^"]*"\s*\+(?!\s*")/i,
    why: "Formatting values into SQL text allows SQL injection.",
    fix: "Use placeholders: db.Query(\"... WHERE id = $1\", id)." }),
  R({ id: "go.shell-exec", langs: ["go"], title: "Command run through a shell", sev: "high", cwe: 78,
    re: /exec\.Command(?:Context)?\s*\((?:ctx\s*,\s*)?"(?:sh|bash|\/bin\/sh|\/bin\/bash|cmd|cmd\.exe)"\s*,\s*"(?:-c|\/c)"\s*,\s*[^")]/,
    why: "Running `sh -c` with a variable string allows command injection.",
    fix: "Call exec.Command with the program and each argument separately." }),
  R({ id: "go.weak-hash-password", langs: ["go"], title: "Weak hash used for passwords", sev: "medium", cwe: 328,
    re: /\b(?:md5|sha1)\.(?:New|Sum)\s*\(/, near: /passw|pwd/i,
    why: "Fast hashes make stolen password hashes cheap to crack.",
    fix: "Use golang.org/x/crypto/bcrypt or argon2." }),
  // PHP
  R({ id: "php.exec-input", langs: ["php"], title: "Request input reaches code/command execution", sev: "critical", cwe: 78,
    re: /\b(?:eval|assert|system|shell_exec|passthru|exec|popen|proc_open)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b/,
    why: "User input passed to eval/system executes attacker-controlled code or commands.",
    fix: "Never pass request input to these functions; use escapeshellarg plus an allowlist if a command is unavoidable." }),
  R({ id: "php.sql-input", langs: ["php"], title: "SQL query built with request input", sev: "high", cwe: 89,
    re: /\b(?:mysqli_query|mysql_query|->query|pg_query)\s*\([^;]*(?:\$_(?:GET|POST|REQUEST|COOKIE)\b|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*\$\w+)/i,
    why: "Interpolating variables into SQL allows SQL injection.",
    fix: "Use PDO or mysqli prepared statements with bound parameters." }),
  R({ id: "php.unserialize", langs: ["php"], title: "unserialize on request input", sev: "high", cwe: 502,
    re: /\bunserialize\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b/,
    why: "PHP object injection can trigger magic methods that lead to code execution.",
    fix: "Use json_decode for untrusted data." }),
  R({ id: "php.include-input", langs: ["php"], title: "File inclusion from request input", sev: "critical", cwe: 98,
    re: /\b(?:include|require)(?:_once)?\s*\(?[^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b/,
    why: "Including a user-chosen path enables local/remote file inclusion and code execution.",
    fix: "Map input to a fixed allowlist of files." }),
  // Java / Kotlin
  R({ id: "java.sql-concat", langs: ["java"], title: "SQL query built with concatenation", sev: "high", cwe: 89,
    re: /\.(?:executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery)\s*\(\s*"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"]*"\s*\+/i,
    why: "Concatenating values into SQL allows SQL injection (and defeats PreparedStatement).",
    fix: "Use PreparedStatement with ? placeholders and setX() bindings." }),
  R({ id: "java.runtime-exec", langs: ["java"], title: "Command built with concatenation", sev: "high", cwe: 78,
    re: /Runtime\.getRuntime\(\)\.exec\s*\(\s*(?:"[^"]*"\s*\+|[a-zA-Z_]\w*\s*\+)/,
    why: "Concatenated command strings allow argument/command injection.",
    fix: "Use ProcessBuilder with a list of fixed arguments." }),
  R({ id: "java.object-input-stream", langs: ["java"], title: "Java native deserialisation", sev: "high", cwe: 502,
    re: /new\s+ObjectInputStream\s*\(/, unless: /setObjectInputFilter|ValidatingObjectInputStream/,
    why: "Deserialising untrusted streams can execute gadget chains (remote code execution).",
    fix: "Use a data format like JSON, or set an ObjectInputFilter allowlist." }),
  R({ id: "java.weak-crypto", langs: ["java"], title: "Weak cryptographic algorithm", sev: "medium", cwe: 327,
    re: /(?:MessageDigest|Cipher)\.getInstance\s*\(\s*"(?:MD5|SHA-?1|DES|DESede|RC4|AES\/ECB[^"]*|AES)"/,
    why: "MD5/SHA-1/DES/RC4 are broken, and AES/ECB (Java's default for \"AES\") leaks patterns in the plaintext.",
    fix: "Use SHA-256+ for digests and AES/GCM/NoPadding for encryption." }),
  R({ id: "java.trust-all", langs: ["java"], title: "Certificate or hostname checks disabled", sev: "high", cwe: 295,
    re: /ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|setHostnameVerifier\s*\(\s*\(?[^)]*\)?\s*->\s*true|checkServerTrusted\s*\([^)]*\)\s*(?:throws\s+\w+\s*)?\{\s*\}/,
    why: "Trusting every certificate or hostname makes HTTPS interceptable.",
    fix: "Use the default TrustManager and HostnameVerifier." }),
  // Dockerfile
  R({ id: "docker.curl-pipe-shell", langs: ["docker", "sh"], title: "Remote script piped into a shell", sev: "medium", cwe: 494,
    re: /\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/,
    why: "The script is executed without integrity verification; a compromised host or MITM runs code in your build.",
    fix: "Download to a file, verify a pinned checksum or signature, then run it." }),
  R({ id: "docker.latest-tag", langs: ["docker"], title: "Base image not pinned", sev: "low", cwe: 1104,
    re: /^\s*FROM\s+(?!scratch\b)[^\s:@]+(?::latest)?(?:\s+AS\s+\w+)?\s*$/i,
    why: "Unpinned or :latest base images change underneath you, making builds non-reproducible and unreviewed.",
    fix: "Pin to a version tag, ideally with an @sha256 digest." }),
  // GitHub Actions
  R({ id: "gha.script-injection", langs: ["gha"], title: "Untrusted event data in a run script", sev: "high", cwe: 94,
    re: /\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|pages)\b[^}]*\.(?:title|body|message|name|label|ref|head_ref)\b[^}]*\}\}|\$\{\{\s*github\.head_ref\s*\}\}/,
    near: /^\s*(?:-\s*)?run\s*:|^\s{2,}\S/, win: 6,
    why: "Attacker-controlled text (PR titles, issue bodies, branch names) is pasted into the shell script before it runs.",
    fix: "Pass the value through an env: variable and reference it as \"$VAR\" in the script." }),
  R({ id: "gha.pr-target-checkout", langs: ["gha"], title: "pull_request_target checks out PR code", sev: "high", cwe: 829,
    re: /ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}/, near: /pull_request_target/, win: 400,
    why: "pull_request_target runs with repo secrets and write token; checking out the fork's code runs untrusted code with them.",
    fix: "Use the pull_request trigger for building PR code, or never execute the checked-out head in this workflow." })
];

// File-level checks that need the whole file (absence of something).
function fileChecks(lang, lines) {
  const out = [];
  if (lang === "docker" && lines.some((l) => /^\s*FROM\s/i.test(l))) {
    const users = lines.map((l, i) => [l, i]).filter(([l]) => /^\s*USER\s+/i.test(l));
    const last = users[users.length - 1];
    if (!last) out.push({ line: lines.findIndex((l) => /^\s*FROM\s/i.test(l)) + 1, rule: DOCKER_ROOT, snippet: "" });
    else if (/^\s*USER\s+(?:root|0)(?::\S+)?\s*$/i.test(last[0])) out.push({ line: last[1] + 1, rule: DOCKER_ROOT, snippet: last[0].trim() });
  }
  return out;
}
const DOCKER_ROOT = { id: "docker.runs-as-root", title: "Container runs as root", sev: "medium", cwe: 250,
  why: "A process running as root inside the container makes any compromise or container escape far more damaging.",
  fix: "Create an unprivileged user and add `USER <name>` before the CMD/ENTRYPOINT." };

// Strip a trailing line comment (outside quotes) so commented-out code is ignored.
function stripComment(line, lang) {
  const marks = lang === "py" || lang === "rb" || lang === "sh" || lang === "yaml" || lang === "gha" || lang === "docker" || lang === "env" || lang === "tf" ? ["#"] : ["//"];
  let q = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === "\\") { i++; continue; } if (c === q) q = ""; continue; }
    if (c === '"' || c === "'" || c === "`") { q = c; continue; }
    for (const m of marks) if (line.startsWith(m, i) && (m !== "//" || line[i - 1] !== ":")) return line.slice(0, i);
  }
  return line;
}

const IGNORE = /darknode-ignore|nosec\b/;
const FLOW_COVERED = new Set(["js.eval", "js.child-process-exec", "js.inner-html", "js.document-write", "js.dangerously-set-html", "js.sql-concat"]);

// scanFile(path, text) → [{ ruleId, title, sev, cwe, line, col, snippet, why, fix, kind, secret? }]
export function scanFile(path, text) {
  const lang = langOf(path);
  const lines = String(text || "").split(/\r?\n/);
  const testy = TESTY_PATH.test(path);
  const out = [];
  const samples = new Set(); // secret-shaped values skipped as examples/placeholders (AKIA...EXAMPLE, sequential tokens) - lets a UI say why "nothing found"
  const seen = new Set();
  const push = (rule, i, col, snippet, extra) => {
    const key = rule.id + ":" + i;
    if (seen.has(key)) return;
    seen.add(key);
    let sev = rule.sev;
    if (testy && (sev === "critical" || sev === "high" || sev === "medium")) sev = rule.id.startsWith("secret.") ? "low" : sev === "critical" ? "high" : sev;
    out.push({ ruleId: rule.id, title: rule.title, sev, cwe: rule.cwe, line: i + 1, col: col + 1, snippet: String(snippet).slice(0, 300), why: rule.why, fix: rule.fix, kind: rule.id.split(".")[0] === "secret" ? "secret" : "code", ...extra });
  };
  let inBlock = false;
  const codeRules = CODE_RULES.filter((r) => r.langs.includes(lang));
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (raw.length > SKIP_LINE || IGNORE.test(raw) || (i > 0 && IGNORE.test(lines[i - 1]) && /darknode-ignore-next-line/.test(lines[i - 1]))) continue;
    // Secrets: scan raw line (secrets are often inside strings/comments too).
    for (const rule of SECRET_RULES) {
      const m = secretHit(rule, raw, path);
      if (!m) continue;
      if (m.placeholder) { samples.add(i + ":" + m.placeholder); continue; }
      const val = m.val;
      if (rule.id !== "secret.private-key" && PLACEHOLDER.test(val)) { samples.add(i + ":" + val); continue; }
      if (rule.minEntropy && entropy(val) < rule.minEntropy) { samples.add(i + ":" + val); continue; }
      if (rule.id === "secret.private-key" && !KEY_BODY.test(raw.slice(m.index)) && !KEY_BODY.test(lines[i + 1] || "")) continue; // a marker in a detector or a doc, no key
      if (rule.id === "secret.db-url" && PLACEHOLDER_PASS.test(val)) continue;
      if (rule.id === "secret.google-api-key" && /authDomain|firebaseapp\.com/.test(lines.slice(Math.max(0, i - 6), i + 7).join("\n"))) continue; // Firebase web config keys are public by design
      if (rule.id === "secret.generic" && (/^[a-z]+(?:[-_.][a-z]+)+$/.test(val) || /^eyJ/.test(val) || SECRET_RULES.some((r) => r.id !== "secret.generic" && secretHit(r, val)))) continue; // a word, not a credential; or a specific rule owns this value
      if (rule.id === "secret.generic" && /^\$(?:2[abxy]?|argon2(?:id|i|d)|scrypt|pbkdf2[\w-]*|[156])\$/.test(val)) continue; // a password HASH, not a secret
      push(rule, i, m.index, raw.trim().replace(val, mask(val)), { secret: mask(val) });
    }
    if (!codeRules.length) continue;
    // Code rules: skip block comments and strip trailing line comments.
    let line = raw;
    if (lang === "js" || lang === "java" || lang === "go" || lang === "php" || lang === "cs") {
      if (inBlock) { const e = line.indexOf("*/"); if (e < 0) continue; line = line.slice(e + 2); inBlock = false; }
      const s = line.indexOf("/*");
      if (s >= 0 && line.indexOf("*/", s + 2) < 0 && !/["'`][^"'`]*\/\*/.test(line.slice(0, s + 2))) { inBlock = true; line = line.slice(0, s); }
    }
    if (/^\s*(?:\/\/|#|\*)/.test(line) && !(lang === "php" && /^\s*#\[/.test(line))) continue;
    line = stripComment(line, lang);
    if (!line.trim()) continue;
    for (const rule of codeRules) {
      const m = rule.re.exec(line);
      if (!m) continue;
      const win = lines.slice(Math.max(0, i - rule.win), i + rule.win + 1).join("\n");
      if (rule.near && !rule.near.test(win)) continue;
      if (rule.unless && (rule.unless.test(line) || rule.unless.test(path))) continue;
      push(rule, i, m.index, raw.trim());
    }
  }
  for (const f of fileChecks(lang, lines)) push(f.rule, Math.max(0, f.line - 1), 0, f.snippet || lines[Math.max(0, f.line - 1)].trim());
  // Data flow (JS/TS): a traced source-to-sink path replaces a pattern hit with the same CWE on that line.
  if (lang === "js" && !/\.(vue|svelte)$/i.test(path) && String(text || "").length <= 600000) {
    let flows = [];
    try { flows = taintScan(text); } catch (_) { /* never let the flow engine break a scan */ }
    for (const t of flows) {
      const i = t.line - 1, raw = lines[i] || "";
      if (IGNORE.test(raw) || (i > 0 && /darknode-ignore-next-line/.test(lines[i - 1]))) continue;
      for (let k = out.length - 1; k >= 0; k--) if (out[k].line === t.line && out[k].cwe === t.cwe && out[k].kind === "code") out.splice(k, 1);
      push({ id: t.ruleId, title: t.title, sev: t.sev, cwe: t.cwe, why: t.why, fix: t.fix }, i, t.col - 1, raw.trim(), { flow: t.flow, confidence: "high" });
    }
    // A sink pattern the flow engine could not connect to any untrusted input is a
    // *needs-review* item: the dangerous call is genuine (a non-constant value reaches a
    // code/command/HTML/SQL sink), but no untrusted source was proven to flow in. It keeps
    // its real severity so it is never silently hidden — it is only labelled lower
    // confidence, and repoScore counts it less than a taint-confirmed finding. Demoting
    // these to "info" (score weight 0, hidden by default) used to drop real bugs the
    // engine simply could not trace, and was inconsistent with files where taint never runs.
    for (const f of out) if (FLOW_COVERED.has(f.ruleId) && f.confidence !== "high") {
      f.confidence = "review";
      f.why = "No untrusted input was traced to this line, so confirm where the value comes from before treating it as exploitable. " + f.why;
    }
  }
  out.placeholders = samples.size;
  return out;
}

// ── Dependency manifests → pinned packages (for OSV.dev querybatch) ────────────
// Returns [{ name, version, ecosystem, line }]; unpinned specs are skipped (OSV
// needs an exact version), and the declaring line lets the viewer jump to it.
export const MANIFESTS = ["package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock", "Pipfile.lock", "go.mod", "Cargo.lock", "Gemfile.lock", "composer.lock", "gradle.lockfile"];
export const isManifest = (path) => MANIFESTS.includes(String(path).split("/").pop()) || /(^|\/)requirements[\w.-]*\.txt$/i.test(path);

// The parsing itself is core/lockfiles.js (shared with Supply Chain and License Audit);
// this keeps the exact pins and names each ecosystem the way OSV.dev does.
export function parseManifest(path, text) {
  let deps = null;
  try { deps = isManifest(path) ? parseLockfile(formatForName(path), String(text || "")) : null; } catch (_) { /* malformed manifest — report nothing rather than guess */ }
  const uniq = new Map();
  for (const d of deps || []) {
    const ecosystem = OSV_ECOSYSTEM[d.ecosystem];
    if (!d.exact || !d.name || !ecosystem || !/^\d/.test(d.version || "")) continue; // ranges resolve differently per install
    const k = ecosystem + "|" + d.name + "|" + d.version;
    if (!uniq.has(k)) uniq.set(k, { name: d.name, version: d.version, ecosystem, line: d.line || 1 });
  }
  return [...uniq.values()];
}

// OSV severity → our scale. Prefer the advisory's own label; fall back to CVSS base.
export function osvSeverity(v) {
  const label = String((v.database_specific && v.database_specific.severity) || "").toLowerCase();
  if (label === "critical" || label === "high" || label === "low") return label;
  if (label === "moderate" || label === "medium") return "medium";
  const score = (v.severity || []).map((s) => cvssBase(s.score)).filter((n) => n != null)[0];
  if (score == null) return "medium";
  return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
}

// CVSS v3.x base score from a vector string (the spec formula; v4 vectors → null).
export function cvssBase(vec) {
  const m = /^CVSS:3\.[01]\/(.+)$/.exec(String(vec || ""));
  if (!m) return null;
  const p = Object.fromEntries(m[1].split("/").map((kv) => kv.split(":")));
  const W = { AV: { N: .85, A: .62, L: .55, P: .2 }, AC: { L: .77, H: .44 }, UI: { N: .85, R: .62 }, C: { H: .56, L: .22, N: 0 } };
  const changed = p.S === "C";
  const PR = { N: .85, L: changed ? .68 : .62, H: changed ? .5 : .27 }[p.PR];
  const [c, i, a] = ["C", "I", "A"].map((k) => W.C[p[k]]);
  if ([W.AV[p.AV], W.AC[p.AC], PR, W.UI[p.UI], c, i, a].some((x) => x == null)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - .029) - 3.25 * Math.pow(iss - .02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const expl = 8.22 * W.AV[p.AV] * W.AC[p.AC] * PR * W.UI[p.UI];
  const up = (x) => { const n = Math.round(x * 100000); return n % 10000 === 0 ? n / 100000 : (Math.floor(n / 10000) + 1) / 10; };
  return up(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}

// Compare two dotted version strings by their numeric release parts; lower sorts first.
// (Prerelease/build suffixes are ignored — enough to pick the lowest fixed release reliably.)
function cmpVer(a, b) {
  const pa = String(a).split(/[.+-]/), pb = String(b).split(/[.+-]/);
  const n = Math.max(pa.length, pb.length);
  for (let k = 0; k < n; k++) {
    const x = parseInt(pa[k], 10), y = parseInt(pb[k], 10);
    const xn = isNaN(x) ? 0 : x, yn = isNaN(y) ? 0 : y;
    if (xn !== yn) return xn - yn;
  }
  return 0;
}

// Lowest "fixed" version for this package across the advisory's affected ranges. OSV lists ranges
// per release branch in no guaranteed order, so the minimal upgrade target is the lowest fixed
// version, not whichever range happens to appear first.
export function osvFixed(v, name) {
  const fixes = [];
  for (const a of v.affected || []) {
    if (a.package && a.package.name && a.package.name.toLowerCase() !== String(name).toLowerCase()) continue;
    for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) fixes.push(e.fixed);
  }
  return fixes.sort(cmpVer)[0] || "";
}

// Dependency advisory hit → finding (shared by the browser scanner, commit watch and CLI).
// `vuln` is the OSV record (null when its detail fetch failed).
export function depFinding(dep, id, vuln, snippet) {
  const alias = vuln && (vuln.aliases || []).find((a) => /^CVE-/.test(a));
  const fixed = vuln ? osvFixed(vuln, dep.name) : "";
  return { kind: "dep", ruleId: "dep." + id, title: (vuln && vuln.summary) || "Known vulnerability in " + dep.name, sev: vuln ? osvSeverity(vuln) : "medium",
    path: dep.path, line: dep.line, col: 1, snippet: snippet || "",
    pkg: dep.name, version: dep.version, ecosystem: dep.ecosystem, advisory: id, cve: alias || "", fixed,
    why: `${dep.name} ${dep.version} (${dep.ecosystem}) is affected by ${id}${alias ? " / " + alias : ""}.`,
    fix: fixed ? `Upgrade ${dep.name} to ${fixed} or later and regenerate the lockfile.` : "No fixed release is listed yet. Check the advisory for mitigations or replace the package." };
}

// A lockfile has the exact resolved versions, so it wins over package.json in the same
// folder. Mutates and returns `deps` ([{ ...dep, path }]).
export function dedupeDeps(deps) {
  const dir = (p) => p.replace(/[^/]*$/, "");
  const locked = new Set(deps.filter((d) => !/(^|\/)package\.json$/.test(d.path)).map((d) => dir(d.path)));
  for (let k = deps.length - 1; k >= 0; k--) if (/(^|\/)package\.json$/.test(deps[k].path) && locked.has(dir(deps[k].path))) deps.splice(k, 1);
  return deps;
}

// Weighted 0–100 score for a scan (100 = no findings). Transparent and simple:
// each finding subtracts by severity, with diminishing returns.
export function repoScore(findings) {
  const w = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };
  // Needs-review findings (a dangerous sink with no traced untrusted source) still count,
  // but at a fraction of a taint-confirmed finding of the same severity — present, never free.
  const pen = findings.reduce((s, f) => s + (w[f.sev] || 0) * (f.confidence === "review" ? 0.4 : 1), 0);
  return Math.max(0, Math.round(100 * Math.exp(-pen / 120)));
}

// SARIF 2.1.0 export (GitHub code scanning can ingest this).
// SARIF artifactLocation.uri is a relative URI: percent-encode each path segment, so a file
// named "my conf.py" or "a#b.js" still resolves to that file in GitHub code scanning.
export const sarifUri = (p) => String(p).replace(/\\/g, "/").replace(/^\/+/, "").split("/").map(encodeURIComponent).join("/");

export function toSarif(findings, meta = {}) {
  const rules = new Map();
  for (const f of findings) if (!rules.has(f.ruleId)) rules.set(f.ruleId, { id: f.ruleId, name: f.title, shortDescription: { text: f.title }, fullDescription: { text: f.why || f.title }, help: { text: f.fix || "" }, properties: { tags: f.cwe ? ["security", "external/cwe/cwe-" + f.cwe] : ["security"] } });
  // GitHub code scanning ranks security alerts by `security-severity` (0-10); a rule takes its worst result.
  const SCORE = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" };
  for (const f of findings) { const p = rules.get(f.ruleId).properties; if (!p["security-severity"] || +(SCORE[f.sev] || 1) > +p["security-severity"]) p["security-severity"] = SCORE[f.sev] || "1.0"; }
  const level = (s) => (s === "critical" || s === "high" ? "error" : s === "medium" ? "warning" : "note");
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0",
    runs: [{ tool: { driver: { name: "Darknode Code Scanner", informationUri: "https://darknode.ai", rules: [...rules.values()] } },
      versionControlProvenance: meta.repo ? [{ repositoryUri: "https://github.com/" + meta.repo, revisionId: meta.sha || undefined }] : undefined,
      results: findings.map((f) => ({ ruleId: f.ruleId, level: level(f.sev), message: { text: f.title + (f.secret ? " (" + f.secret + ")" : "") + (f.pkg ? ": " + f.pkg + "@" + f.version + " " + f.advisory : "") },
        locations: [{ physicalLocation: { artifactLocation: { uri: sarifUri(f.path) }, region: { startLine: f.line, startColumn: f.col || 1 } } }],
        codeFlows: f.flow && f.flow.length ? [{ threadFlows: [{ locations: f.flow.map((s) => ({ location: { physicalLocation: { artifactLocation: { uri: sarifUri(f.path) }, region: { startLine: s.line, startColumn: s.col || 1 } }, message: { text: s.label } } })) }] }] : undefined })) }]
  };
}
