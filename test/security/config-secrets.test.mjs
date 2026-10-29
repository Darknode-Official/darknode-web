// Code Scanner: credentials in config files written without quotes (.env, YAML,
// .properties), Django-style SECRET_KEY assignments, and Slack xoxe- refresh tokens.
import { test, assert, group } from "../harness.mjs";
import { scanFile } from "../../public/js/codescan/rules.js";

const ids = (path, text) => scanFile(path, text).map((f) => f.ruleId);
const V = "Xk9mP2vLq7wZ4";

group("codescan: unquoted secrets in config files", () => {
  test(".env, YAML and .properties values are reported", () => {
    assert.deepEqual(ids(".env", "DB_PASSWORD=" + V), ["secret.generic"]);
    assert.deepEqual(ids(".env.production", "export API_KEY=" + V + " # prod"), ["secret.generic"]);
    assert.deepEqual(ids("config/app.yml", "  password: " + V), ["secret.generic"]);
    assert.deepEqual(ids("app.properties", "db.password=" + V), ["secret.generic"]);
    assert.deepEqual(ids("config.yml", "password: Xk9#mP2vLq7wZ"), ["secret.generic"], "a # inside the value is not a comment");
  });
  test("references, YAML markers, words, numbers and non-secret keys stay silent", () => {
    for (const line of ["TOKEN=${OTHER_TOKEN}", "password: $DB_PASS", "token: !vault |", "max_tokens: 100000",
      "password: correcthorsebattery", "password_hash: " + V, "api_key: changeme", "password: <set-me-2>"])
      assert.deepEqual(ids("config.yml", line), [], line);
  });
  test("the unquoted form is not applied to source code", () => {
    assert.deepEqual(ids("src/a.js", "password = " + V), []);
    assert.deepEqual(ids("src/a.py", "api_key = " + V), []);
  });
});

group("codescan: key names and token prefixes", () => {
  test("SECRET_KEY holds a secret", () => {
    assert.deepEqual(ids("settings.py", 'SECRET_KEY = "Zx9kLmQ2pR7vT4wYb3"'), ["secret.generic"]);
  });
  test("Slack xoxe- tokens are Slack tokens", () => {
    assert.deepEqual(ids("src/a.js", 'const t = "xox' + 'e-1-Q7rT2kLm9xWv4bNp8sZc"'), ["secret.slack-token"]);
  });
});
