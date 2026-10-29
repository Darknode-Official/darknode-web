// Shared secret-detector catalogue (public/js/core/secret-detectors.js) and the four
// scanners built on it: DLP (+ LEAKPROBE), Code Scanner, IaC scanner and Credential
// Auditor. Every detector each scanner had before the merge keeps a positive fixture
// that must still fire through that scanner, and a negative that must not.
//
// Fixture tokens are assembled at run time from a seeded generator, so this file holds
// no literal credential for push protection or the self-scan to trip on.

import { test, assert, group } from "../harness.mjs";
import { SECRET_DETECTORS, DETECTOR_BY_ID, detector, findAll, keyHoldsSecret } from "../../public/js/core/secret-detectors.js";
import { scan as dlpScan, DETECTORS as DLP_DETECTORS } from "../../public/js/dataprotect/dlp-engine.js";
import { scanFile, SECRET_RULES } from "../../public/js/codescan/rules.js";
import { scanSecrets, SECRET_PATTERNS } from "../../public/js/appsec/iacscan-engine.js";
import { scanForKeys } from "../../public/js/credential-auditor.js";

let seed = 20261017;
const rnd = () => ((seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) >>> 8) / 0x1000000;
const ALNUM = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
const UP = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const HEX = "0123456789abcdef";
const B64 = ALNUM + "+/";
const r = (n, set = ALNUM) => Array.from({ length: n }, () => set[Math.floor(rnd() * set.length)]).join("");
const dig = (n) => r(n, "123456789");
const PEM = (t) => "-----" + "BEGIN " + t + "PRIVATE KEY-----";
const PEM_END = (t) => "-----" + "END " + t + "PRIVATE KEY-----";

// coreId -> { pos: text with one real-format secret, neg: a near miss }
export const FIXTURES = {
  "private-key": { pos: PEM("RSA ") + "\n" + r(64, B64) + "\n" + r(64, B64) + "\n" + PEM_END("RSA "), neg: "-----" + "BEGIN PUBLIC KEY-----" },
  "gcp-service-account": { pos: '{"private_key": "' + PEM("") + "\\n" + r(64, B64) + "\\n" + PEM_END("") + '\\n", "client_email": "svc@proj-1.iam.' + 'gserviceaccount.com"}', neg: '{"private_key": "' + PEM("") + '", "client_email": "svc@example.org"}' },
  "aws-key": { pos: "aws_access_key_id = " + "AKIA" + r(16, UP), neg: "user id " + "AIDA" + r(16, UP) },
  "aws-secret": { pos: "aws_secret_access_key = " + r(40, B64), neg: "aws_secret_access_key = " + "A".repeat(40) },
  "gcp-key": { pos: "maps_key: " + "AIza" + r(35), neg: "AIza" + r(20) },
  "google-oauth": { pos: "client_secret " + "GOCSPX-" + r(28), neg: "GOCSPX-" + r(8) },
  "google-oauth-client-id": { pos: dig(12) + "-" + r(32, "abcdefghjkmnpqrstuvwxyz0123456789") + ".apps.googleusercontent.com", neg: "see apps.googleusercontent.com" },
  "github-token": { pos: "token ghp_" + r(36), neg: "ghp_" + r(20) },
  "github-pat-fine": { pos: "github_pat_" + r(22) + "_" + r(59), neg: "github_pat_" + r(22) },
  "gitlab-pat": { pos: "glpat-" + r(20), neg: "glpat-" + r(8) },
  "slack-token": { pos: "xoxb-" + dig(11) + "-" + dig(12) + "-" + r(24), neg: "xoxb-" + dig(4) },
  "slack-app-token": { pos: "xapp-1-A" + r(10, UP) + "-" + dig(13) + "-" + r(64, HEX), neg: "xapp-1-A" + r(4, UP) },
  "slack-webhook": { pos: "https://hooks.slack.com/services/T" + r(8, UP) + "/B" + r(10, UP) + "/" + r(24), neg: "https://hooks.slack.com/services/T000/B000/abc" },
  "stripe-key": { pos: "sk_" + "live_" + r(24), neg: "sk_" + "live_" + r(10) },
  "stripe-test-key": { pos: "sk_" + "test_" + r(24), neg: "sk_" + "test_" + r(10) },
  "stripe-publishable-key": { pos: "pk_" + "live_" + r(24), neg: "pk_" + "live_" + r(10) },
  "openai-key": { pos: "sk-" + "proj-" + r(48), neg: "sk-" + r(20) },
  "anthropic-key": { pos: "sk-" + "ant-api03-" + r(90), neg: "sk-" + "ant-" + r(10) },
  "jwt": { pos: "eyJ" + r(20) + ".eyJ" + r(30) + "." + r(43), neg: "eyJ" + r(5) + ".notatoken" },
  "twilio-account-sid": { pos: "AC" + r(32, HEX), neg: "AC" + r(30, HEX) },
  "twilio-api-key": { pos: "SK" + r(32, HEX), neg: "SK" + r(30, HEX) },
  "twilio-auth-token": { pos: "twilio_auth_token = " + r(32, HEX), neg: "auth_token = " + r(20, HEX) },
  "sendgrid-key": { pos: "SG." + r(22) + "." + r(43), neg: "SG." + r(22) + "." + r(20) },
  "mailgun-key": { pos: "key-" + r(32, HEX), neg: "key-" + r(20, HEX) },
  "npm-token": { pos: "npm_" + r(36), neg: "npm_" + r(20) },
  "huggingface-token": { pos: "hf_" + r(34), neg: "hf_" + r(12) },
  "pypi-token": { pos: "pypi-" + "AgEIcHlwaS5vcmc" + r(60), neg: "pypi-" + r(20) },
  "conn-string": { pos: "postgres://app:" + r(16) + "@db.internal:5432/app", neg: "postgres://db.internal:5432/app" },
  "azure-storage-key": { pos: "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=" + r(86, B64) + "==;", neg: "AccountKey=" + r(20, B64) + "==" },
  "azure-sas": { pos: "https://acct.blob.core.windows.net/c/f?sv=2022-11-02&ss=b&sp=r&se=2026-12-01&sig=" + r(40) + "%3D", neg: "https://acct.blob.core.windows.net/c/f?sv=2022-11-02" },
  "azure-ad-secret": { pos: r(3) + "8Q~" + r(34) + "\nAZURE_CLIENT_SECRET=" + r(40), neg: "AZURE_CLIENT_ID=" + r(40) },
  "heroku-key": { pos: "HEROKU_API_KEY=" + [8, 4, 4, 4, 12].map((n) => r(n, HEX)).join("-"), neg: "request id " + [8, 4, 4, 4, 12].map((n) => r(n, HEX)).join("-") },
  "digitalocean-token": { pos: "dop_v1_" + r(64, HEX), neg: "dop_v1_" + r(20, HEX) },
  "planetscale-token": { pos: "pscale_tkn_" + r(43), neg: "pscale_tkn_" + r(8) },
  "discord-bot-token": { pos: "M" + r(25) + "." + r(6) + "." + r(38), neg: "M" + r(10) + "." + r(6) },
  "telegram-bot-token": { pos: dig(10) + ":" + r(35), neg: dig(10) + ":" + r(12) },
  "datadog-key": { pos: "DD_API_KEY=" + r(32, HEX), neg: "dd" + r(38, HEX) },
  "shopify-token": { pos: "shpat_" + r(32, HEX), neg: "shpat_" + r(20, HEX) },
  "cloudflare-global-key": { pos: "CF_API_KEY=" + r(37, HEX), neg: "CF_API_KEY=" + r(20, HEX) },
  "cloudflare-api-token": { pos: "CF_API_TOKEN=" + r(40), neg: r(40) },
  "bearer-auth": { pos: "Authorization: Bearer " + r(32), neg: "Bearer short" },
  "pat-assignment": { pos: 'db.password = "' + r(16) + '"', neg: 'password = "your-password-here"' },
};

// The former detector sets: scanner id -> core detector id.
export const DLP_IDS = {
  "private-key": "private-key", "aws-secret": "aws-secret", "aws-key": "aws-key", "gcp-key": "gcp-key", "github-token": "github-token",
  "github-pat-fine": "github-pat-fine", "slack-token": "slack-token", "stripe-key": "stripe-key", "openai-key": "openai-key",
  "anthropic-key": "anthropic-key", "google-oauth": "google-oauth", "jwt": "jwt", "slack-webhook": "slack-webhook",
  "twilio-key": "twilio-account-sid", "sendgrid-key": "sendgrid-key", "pat-assignment": "pat-assignment", "conn-string": "conn-string",
  "azure-storage-key": "azure-storage-key", "azure-sas": "azure-sas", "azure-ad-secret": "azure-ad-secret", "gitlab-pat": "gitlab-pat",
  "npm-token": "npm-token", "gcp-service-account": "gcp-service-account", "heroku-key": "heroku-key", "digitalocean-token": "digitalocean-token",
  "bearer-auth": "bearer-auth", "mailgun-key": "mailgun-key", "planetscale-token": "planetscale-token", "slack-app-token": "slack-app-token",
  "huggingface-token": "huggingface-token",
};
export const CODESCAN_IDS = {
  "secret.aws-access-key": "aws-key", "secret.aws-secret-key": "aws-secret", "secret.github-token": "github-token", "secret.slack-token": "slack-token",
  "secret.slack-webhook": "slack-webhook", "secret.stripe-live": "stripe-key", "secret.google-api-key": "gcp-key", "secret.private-key": "private-key",
  "secret.openai-key": "openai-key", "secret.anthropic-key": "anthropic-key", "secret.sendgrid-key": "sendgrid-key", "secret.twilio-key": "twilio-api-key",
  "secret.npm-token": "npm-token", "secret.jwt": "jwt", "secret.db-url": "conn-string", "secret.generic": "pat-assignment",
};
export const IAC_IDS = {
  "SEC-001": "aws-key", "SEC-002": "private-key", "SEC-003": "github-token", "SEC-004": "slack-token", "SEC-005": "gcp-key",
  "SEC-006": "pat-assignment", "SEC-007": "aws-secret", "SEC-008": "stripe-key", "SEC-009": "slack-webhook", "SEC-010": "azure-storage-key",
};
// Credential Auditor names; the ones a prefix narrows get a fixture of that kind.
export const CRED_IDS = {
  "AWS Access Key ID": "aws-key", "AWS Secret Access Key": "aws-secret", "GitHub Personal Access Token (classic)": "github-token",
  "GitHub Fine-Grained Token": "github-pat-fine", "GitHub OAuth Token": ["github-token", "token gho_" + r(36)], "GitHub App Token": ["github-token", "token ghu_" + r(36)],
  "GitLab Personal Access Token": "gitlab-pat", "Stripe Live Secret Key": "stripe-key", "Stripe Test Secret Key": "stripe-test-key",
  "Stripe Publishable Key": "stripe-publishable-key", "Stripe Restricted Key": ["stripe-key", "rk_" + "live_" + r(24)],
  "Slack Bot Token": "slack-token", "Slack User Token": ["slack-token", "xoxp-" + dig(11) + "-" + dig(11) + "-" + dig(12) + "-" + r(32, HEX)],
  "Slack Webhook URL": "slack-webhook", "Google API Key": "gcp-key", "Google OAuth Client ID": "google-oauth-client-id", "Firebase API Key": "gcp-key",
  "Twilio Account SID": "twilio-account-sid", "Twilio Auth Token": "twilio-auth-token", "SendGrid API Key": "sendgrid-key", "Mailgun API Key": "mailgun-key",
  "Heroku API Key": "heroku-key", "DigitalOcean Token": "digitalocean-token", "NPM Token": "npm-token", "PyPI Token": "pypi-token",
  "Anthropic API Key": "anthropic-key", "OpenAI API Key": "openai-key", "Discord Bot Token": "discord-bot-token", "Telegram Bot Token": "telegram-bot-token",
  "Azure Storage Key": "azure-storage-key", "Azure AD Client Secret": "azure-ad-secret", "GCP Service Account Key": "gcp-service-account",
  "JWT Token": "jwt", "Private Key (PEM)": "private-key", "SSH Private Key": ["private-key", PEM("OPENSSH ") + "\n" + r(64, B64) + "\n" + PEM_END("OPENSSH ")],
  "Datadog API Key": "datadog-key", "Shopify Access Token": "shopify-token", "Cloudflare API Key": "cloudflare-global-key", "Cloudflare API Token": "cloudflare-api-token",
};
export const fixture = (v) => (Array.isArray(v) ? { core: v[0], pos: v[1], neg: FIXTURES[v[0]].neg } : { core: v, ...FIXTURES[v] });

group("secret-detectors: the shared catalogue", () => {
  test("ids are unique, every detector has a fixture, and detector() refuses unknown ids", () => {
    assert.equal(new Set(SECRET_DETECTORS.map((d) => d.id)).size, SECRET_DETECTORS.length);
    assert.deepEqual(SECRET_DETECTORS.map((d) => d.id).filter((id) => !FIXTURES[id]), []);
    for (const d of SECRET_DETECTORS) assert.ok(d.re.global && d.name && d.severity, d.id + " needs a global regex, a name and a severity");
    assert.throws(() => detector("no-such-detector"));
  });
  test("each positive fires and each negative stays silent", () => {
    for (const [id, f] of Object.entries(FIXTURES)) {
      assert.ok(findAll(DETECTOR_BY_ID[id], f.pos).length > 0, id + " missed its positive");
      assert.equal(findAll(DETECTOR_BY_ID[id], f.neg).length, 0, id + " fired on its negative: " + f.neg.slice(0, 60));
    }
  });
  test("a shared regex is safe to reuse: a stale lastIndex does not hide the next match", () => {
    const d = DETECTOR_BY_ID["github-token"];
    d.re.lastIndex = 999;
    assert.equal(findAll(d, FIXTURES["github-token"].pos).length, 1);
  });
  test("keyHoldsSecret reads the last key segment", () => {
    assert.ok(keyHoldsSecret("db.password") && keyHoldsSecret("my-api-key") && keyHoldsSecret("client_secret"));
    assert.ok(!keyHoldsSecret("password_length") && !keyHoldsSecret("secret_name"));
    assert.ok(!keyHoldsSecret("db_password", "."), "underscore joins words unless named as a separator");
  });
});

group("secret-detectors: forms only one former version knew still fire", () => {
  test("legacy 48-character OpenAI keys and project keys are both openai-key; Anthropic keys are not", () => {
    const legacy = "sk-" + r(48), proj = FIXTURES["openai-key"].pos, ant = FIXTURES["anthropic-key"].pos;
    for (const t of [legacy, proj]) assert.ok(findAll(DETECTOR_BY_ID["openai-key"], t).length === 1, t.slice(0, 12));
    assert.equal(findAll(DETECTOR_BY_ID["openai-key"], ant).length, 0, "an sk-ant- key is reported once, as Anthropic");
    assert.ok(scanForKeys(legacy).some((x) => x.name === "OpenAI API Key"));
  });
  test("Azure AD secrets: the Q~ format (DLP) and an AZURE_CLIENT_SECRET assignment (Credential Auditor)", () => {
    const [q, assign] = FIXTURES["azure-ad-secret"].pos.split("\n");
    for (const t of [q, assign]) assert.ok(dlpScan(t).findings.some((x) => x.id === "azure-ad-secret") && scanForKeys(t).some((x) => x.name === "Azure AD Client Secret"), t.slice(0, 24));
  });
  test("AWS secret keys in quoted JSON and in bare assignments", () => {
    const v = r(40, B64);
    for (const t of ['"aws_secret_access_key": "' + v + '"', "secret_key=" + v, "AWS_SECRET_ACCESS_KEY: " + v]) assert.ok(findAll(DETECTOR_BY_ID["aws-secret"], t).length === 1, t.slice(0, 30));
  });
});

group("secret-detectors: former DLP detectors (LEAKPROBE reuses these)", () => {
  test("the DLP set is the same 29 secret ids as before, mapped to the catalogue", () => {
    assert.deepEqual(DLP_DETECTORS.filter((d) => d.kind === "secret").map((d) => d.id).sort(), Object.keys(DLP_IDS).sort());
  });
  for (const [id, core] of Object.entries(DLP_IDS)) test(id, () => {
    const f = fixture(core);
    assert.ok(dlpScan(f.pos).findings.some((x) => x.id === id), id + " missed its positive");
    assert.ok(!dlpScan(f.neg).findings.some((x) => x.id === id), id + " fired on its negative");
  });
});

group("secret-detectors: former Code Scanner rules", () => {
  test("the rule set is the same 16 ids as before", () => {
    assert.deepEqual(SECRET_RULES.map((x) => x.id).sort(), Object.keys(CODESCAN_IDS).sort());
  });
  const ids = (text) => scanFile("src/settings.js", text + "\n").map((x) => x.ruleId);
  for (const [id, core] of Object.entries(CODESCAN_IDS)) test(id, () => {
    const f = core === "pat-assignment" ? { pos: 'config.password = "' + r(16) + '"', neg: 'password_hint = "' + r(16) + '"' } : fixture(core);
    assert.ok(ids(f.pos).includes(id), id + " missed its positive: " + f.pos.slice(0, 80));
    assert.ok(!ids(f.neg).includes(id), id + " fired on its negative");
  });
  test("secret.generic: a credential word ending a snake/kebab key counts (db_password, DB_PASSWORD, github-token); one inside it does not", () => {
    for (const k of ["db_password", "DB_PASSWORD", "github-token", "stripe_api_key"]) assert.ok(ids(k + ' = "' + r(16) + '"').includes("secret.generic"), k);
    for (const k of ["password_hint", "max_tokens", "token_type", "secret_name"]) assert.ok(!ids(k + ' = "' + r(16) + '"').includes("secret.generic"), k);
  });
  test("a live key keeps its severity in pasted code and in a .txt file (keys.txt is a classic leak); docs still soften it", () => {
    const line = 'k = "sk_live_' + r(32) + '"\n', sev = (p) => (scanFile(p, line).find((x) => x.ruleId === "secret.stripe-live") || {}).sev;
    assert.equal(sev("pasted code"), "critical"); assert.equal(sev("keys.txt"), "critical"); assert.equal(sev("README.md"), "low");
  });
});

group("secret-detectors: former IaC scanner patterns", () => {
  test("the pattern set is the same 10 ids as before", () => {
    assert.deepEqual(SECRET_PATTERNS.map((x) => x.id), Object.keys(IAC_IDS));
  });
  for (const [id, core] of Object.entries(IAC_IDS)) test(id, () => {
    const f = fixture(core);
    assert.ok(scanSecrets(f.pos).some((h) => h.ruleId === id), id + " missed its positive");
    assert.ok(!scanSecrets(f.neg).some((h) => h.ruleId === id), id + " fired on its negative");
  });
  test("fine-grained GitHub tokens are SEC-003 too", () => {
    assert.ok(scanSecrets(FIXTURES["github-pat-fine"].pos).some((h) => h.ruleId === "SEC-003"));
  });
});

group("secret-detectors: former Credential Auditor key patterns", () => {
  for (const [name, spec] of Object.entries(CRED_IDS)) test(name, () => {
    const f = fixture(spec);
    const hit = scanForKeys(f.pos).find((x) => x.name === name);
    assert.ok(hit, name + " missed its positive");
    assert.ok(hit.value.includes("...") && !f.pos.includes(hit.value), "the value is masked");
    assert.ok(!scanForKeys(f.neg).some((x) => x.name === name), name + " fired on its negative");
  });
  test("a prefix narrows a shared detector to one token kind", () => {
    const names = scanForKeys("token gho_" + r(36)).map((x) => x.name);
    assert.ok(names.includes("GitHub OAuth Token") && !names.includes("GitHub Personal Access Token (classic)"));
  });
});
