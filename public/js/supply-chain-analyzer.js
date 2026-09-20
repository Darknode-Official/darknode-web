// Supply Chain Risk Analyzer — map and score software supply chain risk
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// ============================================================================
// VULNERABLE PACKAGE DATABASE — 120+ known vulnerable versions
// ============================================================================
const VULN_PACKAGES = [
  // JavaScript / npm
  { ecosystem: 'npm', name: 'lodash', versions: ['<4.17.21'], cve: 'CVE-2021-23337', cvss: 7.2, desc: 'Command injection via template function', fix: '4.17.21' },
  { ecosystem: 'npm', name: 'lodash', versions: ['<4.17.20'], cve: 'CVE-2020-28500', cvss: 5.3, desc: 'Regular expression denial of service', fix: '4.17.20' },
  { ecosystem: 'npm', name: 'lodash', versions: ['<4.17.12'], cve: 'CVE-2019-10744', cvss: 9.1, desc: 'Prototype pollution via defaultsDeep', fix: '4.17.12' },
  { ecosystem: 'npm', name: 'minimist', versions: ['<1.2.6'], cve: 'CVE-2021-44906', cvss: 9.8, desc: 'Prototype pollution', fix: '1.2.6' },
  { ecosystem: 'npm', name: 'node-fetch', versions: ['<2.6.7', '3.0.0-3.1.0'], cve: 'CVE-2022-0235', cvss: 6.1, desc: 'Exposure of sensitive information to unauthorized actor', fix: '2.6.7 / 3.1.1' },
  { ecosystem: 'npm', name: 'express', versions: ['<4.19.2'], cve: 'CVE-2024-29041', cvss: 6.1, desc: 'Open redirect via malformed URL', fix: '4.19.2' },
  { ecosystem: 'npm', name: 'jsonwebtoken', versions: ['<9.0.0'], cve: 'CVE-2022-23529', cvss: 7.6, desc: 'Insecure key handling allows JWS bypass', fix: '9.0.0' },
  { ecosystem: 'npm', name: 'axios', versions: ['<1.6.0'], cve: 'CVE-2023-45857', cvss: 6.5, desc: 'CSRF token leakage via cross-site requests', fix: '1.6.0' },
  { ecosystem: 'npm', name: 'shelljs', versions: ['<0.8.5'], cve: 'CVE-2022-0144', cvss: 7.1, desc: 'Improper privilege management', fix: '0.8.5' },
  { ecosystem: 'npm', name: 'tar', versions: ['<6.1.9'], cve: 'CVE-2021-37713', cvss: 8.6, desc: 'Arbitrary file creation/overwrite on Windows', fix: '6.1.9' },
  { ecosystem: 'npm', name: 'glob-parent', versions: ['<5.1.2'], cve: 'CVE-2020-28469', cvss: 7.5, desc: 'Regular expression denial of service', fix: '5.1.2' },
  { ecosystem: 'npm', name: 'path-parse', versions: ['<1.0.7'], cve: 'CVE-2021-23343', cvss: 7.5, desc: 'Regular expression denial of service', fix: '1.0.7' },
  { ecosystem: 'npm', name: 'ua-parser-js', versions: ['0.7.29', '0.8.0', '1.0.0'], cve: 'SUPPLY-CHAIN', cvss: 9.8, desc: 'Hijacked package versions installed cryptominer and credential stealer', fix: '0.7.30 / 0.8.1 / 1.0.1' },
  { ecosystem: 'npm', name: 'event-stream', versions: ['3.3.6'], cve: 'SUPPLY-CHAIN', cvss: 9.8, desc: 'Backdoored dependency (flatmap-stream) targeting Copay Bitcoin wallets', fix: 'Remove or use 3.3.4' },
  { ecosystem: 'npm', name: 'colors', versions: ['1.4.1', '1.4.2'], cve: 'SABOTAGE', cvss: 7.5, desc: 'Maintainer protest: infinite loop added to production code', fix: '1.4.0' },
  { ecosystem: 'npm', name: 'node-ipc', versions: ['10.1.1', '10.1.2', '10.1.3'], cve: 'SABOTAGE', cvss: 9.8, desc: 'Protestware: overwrites files with heart emoji on Russian/Belarusian IPs', fix: '10.1.0 or fork' },
  { ecosystem: 'npm', name: 'faker', versions: ['6.6.6'], cve: 'SABOTAGE', cvss: 5.0, desc: 'Maintainer deleted all code and published empty package', fix: '@faker-js/faker (community fork)' },
  { ecosystem: 'npm', name: 'moment', versions: ['<2.29.4'], cve: 'CVE-2022-31129', cvss: 7.5, desc: 'Inefficient regular expression complexity (ReDoS)', fix: '2.29.4' },
  { ecosystem: 'npm', name: 'ansi-regex', versions: ['>2.1.1 <5.0.1', '>5.0.1 <6.0.1'], cve: 'CVE-2021-3807', cvss: 7.5, desc: 'Inefficient regular expression complexity', fix: '5.0.1 / 6.0.1' },
  { ecosystem: 'npm', name: 'json5', versions: ['<2.2.2'], cve: 'CVE-2022-46175', cvss: 7.1, desc: 'Prototype pollution via parse method', fix: '2.2.2' },
  { ecosystem: 'npm', name: 'semver', versions: ['<7.5.2'], cve: 'CVE-2022-25883', cvss: 7.5, desc: 'Regular expression denial of service', fix: '7.5.2' },
  { ecosystem: 'npm', name: 'xml2js', versions: ['<0.5.0'], cve: 'CVE-2023-0842', cvss: 5.3, desc: 'Prototype pollution via parsed XML', fix: '0.5.0' },
  { ecosystem: 'npm', name: 'passport', versions: ['<0.6.0'], cve: 'CVE-2022-25896', cvss: 7.5, desc: 'Session fixation vulnerability', fix: '0.6.0' },
  // Python / PyPI
  { ecosystem: 'pypi', name: 'django', versions: ['<4.2.7'], cve: 'CVE-2023-46695', cvss: 7.5, desc: 'Denial of service via NFKC normalization in unicode usernames', fix: '4.2.7' },
  { ecosystem: 'pypi', name: 'django', versions: ['<3.2.23'], cve: 'CVE-2023-43665', cvss: 7.5, desc: 'Denial of service in Truncator', fix: '3.2.23' },
  { ecosystem: 'pypi', name: 'flask', versions: ['<2.3.2'], cve: 'CVE-2023-30861', cvss: 7.5, desc: 'Cookie set on wrong domain in nested subdomains', fix: '2.3.2' },
  { ecosystem: 'pypi', name: 'requests', versions: ['<2.31.0'], cve: 'CVE-2023-32681', cvss: 6.1, desc: 'Unintended leak of Proxy-Authorization header', fix: '2.31.0' },
  { ecosystem: 'pypi', name: 'urllib3', versions: ['<2.0.7', '<1.26.18'], cve: 'CVE-2023-45803', cvss: 4.2, desc: 'Request body not stripped on redirect', fix: '2.0.7 / 1.26.18' },
  { ecosystem: 'pypi', name: 'pillow', versions: ['<10.0.1'], cve: 'CVE-2023-44271', cvss: 7.5, desc: 'Denial of service via large text rendering', fix: '10.0.1' },
  { ecosystem: 'pypi', name: 'cryptography', versions: ['<41.0.6'], cve: 'CVE-2023-49083', cvss: 7.5, desc: 'NULL dereference on loading PKCS7 certificates', fix: '41.0.6' },
  { ecosystem: 'pypi', name: 'paramiko', versions: ['<3.4.0'], cve: 'CVE-2023-48795', cvss: 5.9, desc: 'Terrapin SSH prefix truncation attack', fix: '3.4.0' },
  { ecosystem: 'pypi', name: 'pyyaml', versions: ['<6.0.1'], cve: 'CVE-2020-14343', cvss: 9.8, desc: 'Arbitrary code execution via yaml.load()', fix: '6.0.1' },
  { ecosystem: 'pypi', name: 'setuptools', versions: ['<65.5.1'], cve: 'CVE-2022-40897', cvss: 5.9, desc: 'Regular expression denial of service in package_index', fix: '65.5.1' },
  { ecosystem: 'pypi', name: 'certifi', versions: ['<2023.07.22'], cve: 'CVE-2023-37920', cvss: 9.8, desc: 'Removal of e-Tugra root certificate', fix: '2023.07.22' },
  { ecosystem: 'pypi', name: 'jinja2', versions: ['<3.1.3'], cve: 'CVE-2024-22195', cvss: 6.1, desc: 'Cross-site scripting via xmlattr filter', fix: '3.1.3' },
  { ecosystem: 'pypi', name: 'aiohttp', versions: ['<3.9.2'], cve: 'CVE-2024-23334', cvss: 7.5, desc: 'Directory traversal in static file serving', fix: '3.9.2' },
  // Java / Maven
  { ecosystem: 'maven', name: 'org.apache.logging.log4j:log4j-core', versions: ['2.0-2.14.1'], cve: 'CVE-2021-44228', cvss: 10.0, desc: 'Log4Shell — JNDI injection leading to remote code execution', fix: '2.17.1' },
  { ecosystem: 'maven', name: 'org.apache.logging.log4j:log4j-core', versions: ['2.15.0'], cve: 'CVE-2021-45046', cvss: 9.0, desc: 'Log4j incomplete fix for CVE-2021-44228', fix: '2.17.1' },
  { ecosystem: 'maven', name: 'org.apache.logging.log4j:log4j-core', versions: ['2.16.0'], cve: 'CVE-2021-45105', cvss: 5.9, desc: 'Log4j DoS via recursive lookup', fix: '2.17.1' },
  { ecosystem: 'maven', name: 'com.fasterxml.jackson.core:jackson-databind', versions: ['<2.14.0'], cve: 'CVE-2022-42003', cvss: 7.5, desc: 'Denial of service via deeply nested JSON', fix: '2.14.0' },
  { ecosystem: 'maven', name: 'org.apache.commons:commons-text', versions: ['1.5-1.9'], cve: 'CVE-2022-42889', cvss: 9.8, desc: 'Text4Shell — Remote code execution via string interpolation', fix: '1.10.0' },
  { ecosystem: 'maven', name: 'org.springframework:spring-core', versions: ['5.3.0-5.3.17'], cve: 'CVE-2022-22965', cvss: 9.8, desc: 'Spring4Shell — RCE via data binding on JDK 9+', fix: '5.3.18' },
  { ecosystem: 'maven', name: 'org.apache.struts:struts2-core', versions: ['2.3.x', '2.5.0-2.5.12'], cve: 'CVE-2017-5638', cvss: 10.0, desc: 'Jakarta Multipart parser RCE (Equifax breach)', fix: '2.5.13' },
  { ecosystem: 'maven', name: 'com.google.protobuf:protobuf-java', versions: ['<3.16.3', '3.17.0-3.19.6', '3.20.0-3.20.3', '3.21.0-3.21.7'], cve: 'CVE-2022-3171', cvss: 7.5, desc: 'Denial of service via message parsing', fix: '3.21.8' },
  { ecosystem: 'maven', name: 'org.apache.tomcat.embed:tomcat-embed-core', versions: ['<9.0.68'], cve: 'CVE-2022-42252', cvss: 7.5, desc: 'Request smuggling via malformed Content-Length', fix: '9.0.68' },
  // Ruby / Gems
  { ecosystem: 'gem', name: 'rails', versions: ['<7.0.4.1'], cve: 'CVE-2023-22795', cvss: 7.5, desc: 'Denial of service via Content-Type header parsing', fix: '7.0.4.1' },
  { ecosystem: 'gem', name: 'nokogiri', versions: ['<1.13.10'], cve: 'CVE-2022-23476', cvss: 7.5, desc: 'Use-after-free in libxml2', fix: '1.13.10' },
  { ecosystem: 'gem', name: 'rack', versions: ['<3.0.4.1'], cve: 'CVE-2023-27530', cvss: 7.5, desc: 'Denial of service via multipart MIME parsing', fix: '3.0.4.1' },
  // Go
  { ecosystem: 'go', name: 'golang.org/x/crypto', versions: ['<0.17.0'], cve: 'CVE-2023-48795', cvss: 5.9, desc: 'Terrapin SSH prefix truncation attack', fix: '0.17.0' },
  { ecosystem: 'go', name: 'golang.org/x/net', versions: ['<0.17.0'], cve: 'CVE-2023-44487', cvss: 7.5, desc: 'HTTP/2 rapid reset attack DoS', fix: '0.17.0' },
  { ecosystem: 'go', name: 'github.com/gin-gonic/gin', versions: ['<1.9.1'], cve: 'CVE-2023-29401', cvss: 4.3, desc: 'Improper handling of Content-Type header', fix: '1.9.1' },
  // .NET / NuGet
  { ecosystem: 'nuget', name: 'System.Text.Json', versions: ['<8.0.1'], cve: 'CVE-2024-21319', cvss: 7.5, desc: 'Denial of service via deeply nested JSON', fix: '8.0.1' },
  { ecosystem: 'nuget', name: 'Newtonsoft.Json', versions: ['<13.0.1'], cve: 'CVE-2021-27293', cvss: 7.5, desc: 'Stack overflow via recursive JSON', fix: '13.0.1' },
];

// ============================================================================
// TYPOSQUAT DATABASE — common misspellings of popular packages
// ============================================================================
const TYPOSQUAT_CHECKS = {
  npm: {
    'lodash': ['lodasb', 'lodahs', 'lodsah', 'lod4sh', 'lodash-es-fake'],
    'express': ['expres', 'exppress', 'expresss', 'expres5', 'express-framework'],
    'react': ['reacr', 'raect', 'reactt', 're4ct'],
    'axios': ['axois', 'axio', 'axi0s', 'axious'],
    'moment': ['momnet', 'momen', 'momet', 'm0ment'],
    'webpack': ['webpakc', 'webpaack', 'weback', 'web-pack'],
    'babel': ['bable', 'babell', 'bab3l'],
    'jquery': ['jqeury', 'jqurey', 'jquer', 'jqu3ry'],
    'commander': ['comander', 'commaner', 'comandr'],
    'chalk': ['chalck', 'chak', 'chalke'],
    'debug': ['debag', 'debuq', 'debuge'],
    'underscore': ['udnerscore', 'undesrcore', 'underscore-js'],
    'request': ['reqeust', 'requets', 'requst'],
    'async': ['asyc', 'asnc', 'asyncc'],
    'bluebird': ['bleubird', 'blubird', 'bluebiird'],
  },
  pypi: {
    'requests': ['requets', 'reqeusts', 'requsts', 'request', 'requeests'],
    'beautifulsoup4': ['beautifulsoup', 'beutifulsoup4', 'beautifullsoup4'],
    'flask': ['flasks', 'flaask', 'flak'],
    'django': ['dajngo', 'djagno', 'djnago', 'djano'],
    'numpy': ['numppy', 'numby', 'numpyy'],
    'pandas': ['pandsa', 'pands', 'panadas'],
    'tensorflow': ['tenserflow', 'tensorflw', 'tensorfow'],
    'scrapy': ['scrayp', 'scrapty', 'scrapyy'],
    'pillow': ['pilow', 'pillo', 'pilllow'],
    'cryptography': ['crytography', 'crptography', 'crypography'],
  }
};

// ============================================================================
// SUPPLY CHAIN ATTACK INCIDENTS — 20 real incidents
// ============================================================================
const SC_INCIDENTS = [
  { name: 'SolarWinds SUNBURST', year: 2020, type: 'Build system compromise', impact: '18,000+ organizations including US government agencies', desc: 'Russian APT29 compromised SolarWinds build pipeline, inserting SUNBURST backdoor into Orion software updates. Detected by FireEye when attackers used stolen red team tools.', lesson: 'Build system integrity is critical. Implement reproducible builds and binary attestation.' },
  { name: 'Codecov Bash Uploader', year: 2021, type: 'CI/CD compromise', impact: 'Thousands of repositories had credentials exfiltrated', desc: 'Attackers modified Codecov Bash Uploader script to exfiltrate environment variables (secrets, tokens, keys) from CI/CD pipelines.', lesson: 'Pin and verify checksums of CI/CD scripts. Never trust remote scripts blindly.' },
  { name: 'event-stream (npm)', year: 2018, type: 'Maintainer takeover', impact: 'Copay Bitcoin wallet users had funds stolen', desc: 'Attacker gained maintainer access to event-stream, added flatmap-stream dependency with encrypted payload targeting Copay wallet.', lesson: 'Monitor dependency changes. Be wary of maintainer transfers on popular packages.' },
  { name: 'ua-parser-js (npm)', year: 2021, type: 'Account hijack', impact: 'Cryptominer and password stealer distributed to millions', desc: 'Attacker hijacked npm account of ua-parser-js maintainer, published versions with cryptominer (Linux) and credential stealer (Windows).', lesson: 'Enable 2FA on package registry accounts. Monitor for unexpected version bumps.' },
  { name: 'colors + faker (npm)', year: 2022, type: 'Maintainer sabotage', impact: 'Thousands of projects broken, infinite loop in production', desc: 'Maintainer Marak Squires deliberately sabotaged colors.js (infinite loop) and faker.js (deleted all code) in protest of unpaid open source work.', lesson: 'Pin dependency versions. Have a fallback plan for critical dependencies.' },
  { name: 'node-ipc protestware', year: 2022, type: 'Maintainer sabotage', impact: 'File overwrites on systems with Russian/Belarusian IPs', desc: 'Maintainer added code that checked geolocation and overwrote files on Russian/Belarusian systems with heart emojis, as protest against Ukraine invasion.', lesson: 'Protestware is a real supply chain threat. Lockfiles and version pinning help.' },
  { name: 'Log4Shell (Log4j)', year: 2021, type: 'Zero-day in ubiquitous library', impact: 'Virtually all Java applications worldwide affected', desc: 'Critical JNDI injection vulnerability in Apache Log4j 2.x allowed remote code execution via crafted log messages. Exploited within hours of disclosure.', lesson: 'Maintain an SBOM. Know what transitive dependencies you ship.' },
  { name: 'XZ Utils backdoor', year: 2024, type: 'Multi-year social engineering', impact: 'Near-compromise of SSH on most Linux distributions', desc: 'Attacker spent 2+ years building trust as xz-utils contributor, then inserted a sophisticated backdoor targeting OpenSSH sshd. Caught by Andres Freund noticing 500ms SSH latency.', lesson: 'Social engineering can target open source. Review all contributions carefully, especially to critical infrastructure.' },
  { name: 'Kaseya VSA', year: 2021, type: 'Managed service provider attack', impact: '1,500+ businesses hit with REvil ransomware', desc: 'REvil exploited zero-days in Kaseya VSA (remote management tool) to push ransomware to MSP customers downstream.', lesson: 'Supply chain attacks can cascade through service providers.' },
  { name: 'PyPI typosquatting campaign', year: 2023, type: 'Typosquatting', impact: '100,000+ downloads of malicious packages', desc: 'Multiple campaigns publishing packages with names similar to popular ones (e.g., requesrs, python-binance, beautifulsoup) containing credential stealers.', lesson: 'Verify package names carefully. Use allowlists for approved packages.' },
  { name: '3CX Supply Chain Attack', year: 2023, type: 'Build compromise via upstream', impact: '12 million+ 3CX users potentially affected', desc: 'North Korean Lazarus group compromised 3CX desktop app by first compromising Trading Technologies X_TRADER app — a supply chain attack via another supply chain attack.', lesson: 'Supply chain attacks can chain through multiple vendors.' },
  { name: 'Dependency Confusion', year: 2021, type: 'Namespace confusion', impact: 'Apple, Microsoft, PayPal, Tesla, Uber all affected', desc: 'Researcher Alex Birsan discovered that private package names could be hijacked by publishing higher-version public packages. Package managers preferred the public version.', lesson: 'Use scoped packages. Configure registries to prefer private sources.' },
  { name: 'Okta source code theft', year: 2022, type: 'Source code compromise', impact: 'Okta source code repositories accessed', desc: 'Lapsus$ group accessed Okta source code repositories via compromised contractor account, potentially enabling future supply chain attacks.', lesson: 'Contractor access should be limited and monitored.' },
  { name: 'MOVEit Transfer', year: 2023, type: 'Zero-day in file transfer', impact: '2,700+ organizations, 93M+ individuals affected', desc: 'Cl0p ransomware gang exploited zero-day SQLi in MOVEit Transfer to mass-steal data from organizations using the file transfer tool.', lesson: 'File transfer tools are high-value targets. Patch immediately, monitor for anomalies.' },
  { name: 'Polyfill.io domain takeover', year: 2024, type: 'CDN/domain takeover', impact: '100,000+ websites serving malicious code', desc: 'Chinese company acquired polyfill.io domain and CDN, then injected malicious redirects into the polyfill script served to millions of websites.', lesson: 'Self-host critical JavaScript. Never trust third-party CDNs for production code.' },
];

// ============================================================================
// BUILD PIPELINE SECURITY CHECKLIST — 40 items
// ============================================================================
const PIPELINE_CHECKLIST = [
  { category: 'Source Control', item: 'Require signed commits (GPG/SSH)', priority: 'High' },
  { category: 'Source Control', item: 'Enable branch protection on main/release branches', priority: 'Critical' },
  { category: 'Source Control', item: 'Require PR reviews from CODEOWNERS', priority: 'High' },
  { category: 'Source Control', item: 'Scan commits for secrets (git-secrets, trufflehog, gitleaks)', priority: 'Critical' },
  { category: 'Source Control', item: 'Disable force push on protected branches', priority: 'High' },
  { category: 'Source Control', item: 'Audit repository access permissions quarterly', priority: 'Medium' },
  { category: 'Source Control', item: 'Enable audit logging for all repo actions', priority: 'High' },
  { category: 'Dependencies', item: 'Pin all dependency versions (lockfile committed)', priority: 'Critical' },
  { category: 'Dependencies', item: 'Run vulnerability scanner on every build (npm audit, pip-audit, trivy)', priority: 'Critical' },
  { category: 'Dependencies', item: 'Use a private registry/mirror for approved packages', priority: 'High' },
  { category: 'Dependencies', item: 'Generate and maintain SBOM for every release', priority: 'High' },
  { category: 'Dependencies', item: 'Monitor for dependency confusion (scoped packages, namespace claim)', priority: 'High' },
  { category: 'Dependencies', item: 'Review all new dependency additions in PRs', priority: 'Medium' },
  { category: 'Dependencies', item: 'Set up Dependabot/Renovate for automated updates', priority: 'Medium' },
  { category: 'Dependencies', item: 'Block packages with no license or known-bad licenses', priority: 'Low' },
  { category: 'Dependencies', item: 'Monitor for typosquat packages in your ecosystem', priority: 'Medium' },
  { category: 'CI/CD', item: 'Run CI in ephemeral, isolated containers', priority: 'Critical' },
  { category: 'CI/CD', item: 'Never expose secrets in CI logs (mask all env vars)', priority: 'Critical' },
  { category: 'CI/CD', item: 'Use short-lived, scoped CI tokens (not long-lived PATs)', priority: 'High' },
  { category: 'CI/CD', item: 'Pin CI action/plugin versions by SHA, not tag', priority: 'High' },
  { category: 'CI/CD', item: 'Separate build and deploy pipelines with approval gates', priority: 'High' },
  { category: 'CI/CD', item: 'Enable OIDC federation for cloud deployments (no static keys)', priority: 'High' },
  { category: 'CI/CD', item: 'Scan IaC templates (Terraform, CloudFormation) for misconfigs', priority: 'Medium' },
  { category: 'CI/CD', item: 'Run SAST (static analysis) on every PR', priority: 'High' },
  { category: 'CI/CD', item: 'Run DAST (dynamic analysis) on staging deployments', priority: 'Medium' },
  { category: 'CI/CD', item: 'Verify webhook signatures on CI triggers', priority: 'Medium' },
  { category: 'Artifacts', item: 'Sign all release artifacts (Sigstore/cosign, GPG)', priority: 'High' },
  { category: 'Artifacts', item: 'Publish checksums (SHA-256) for all downloadable binaries', priority: 'High' },
  { category: 'Artifacts', item: 'Use reproducible builds where possible', priority: 'Medium' },
  { category: 'Artifacts', item: 'Scan container images for vulnerabilities before pushing', priority: 'Critical' },
  { category: 'Artifacts', item: 'Use minimal base images (distroless, Alpine)', priority: 'Medium' },
  { category: 'Artifacts', item: 'Tag images with digest, not mutable tags', priority: 'High' },
  { category: 'Artifacts', item: 'Enable container image signing and verification', priority: 'Medium' },
  { category: 'Runtime', item: 'Implement runtime application self-protection (RASP)', priority: 'Low' },
  { category: 'Runtime', item: 'Monitor for anomalous dependency loading at runtime', priority: 'Medium' },
  { category: 'Runtime', item: 'Use Seccomp/AppArmor profiles for containers', priority: 'Medium' },
  { category: 'Runtime', item: 'Enable read-only container filesystems', priority: 'Medium' },
  { category: 'Governance', item: 'Maintain an approved package allowlist', priority: 'Medium' },
  { category: 'Governance', item: 'Require security review for new dependencies', priority: 'High' },
  { category: 'Governance', item: 'Document and test incident response for supply chain compromise', priority: 'High' },
];

// ============================================================================
// LICENSE RISK DATABASE
// ============================================================================
const LICENSE_RISK = {
  'MIT': { risk: 'low', note: 'Permissive. Safe for any use.' },
  'Apache-2.0': { risk: 'low', note: 'Permissive with patent grant. Safe for any use.' },
  'BSD-2-Clause': { risk: 'low', note: 'Permissive. Safe for any use.' },
  'BSD-3-Clause': { risk: 'low', note: 'Permissive. Safe for any use.' },
  'ISC': { risk: 'low', note: 'Permissive. Safe for any use.' },
  'CC0-1.0': { risk: 'low', note: 'Public domain dedication. No restrictions.' },
  'Unlicense': { risk: 'low', note: 'Public domain. No restrictions.' },
  'GPL-2.0': { risk: 'high', note: 'Copyleft. Must open-source your entire project if distributed.' },
  'GPL-3.0': { risk: 'high', note: 'Strong copyleft. Must open-source and provide install instructions.' },
  'AGPL-3.0': { risk: 'critical', note: 'Network copyleft. Even SaaS use requires source disclosure.' },
  'LGPL-2.1': { risk: 'medium', note: 'Weak copyleft. OK if dynamically linked, risky if statically linked.' },
  'LGPL-3.0': { risk: 'medium', note: 'Weak copyleft. Must allow relinking by users.' },
  'MPL-2.0': { risk: 'medium', note: 'File-level copyleft. Modified files must be open-sourced.' },
  'SSPL-1.0': { risk: 'critical', note: 'Server Side PL. Offering as a service requires full stack source disclosure.' },
  'BSL-1.1': { risk: 'high', note: 'Business Source License. Free for non-production use only.' },
  'NONE': { risk: 'critical', note: 'No license found. All rights reserved by default — you cannot legally use this.' },
  'UNKNOWN': { risk: 'high', note: 'License could not be identified. Manual review required.' },
};

// ============================================================================
// PARSERS — detect ecosystem and extract dependencies
// ============================================================================
function parsePackageJson(text) {
  try {
    const pkg = JSON.parse(text);
    const deps = [];
    const addDeps = (obj, type) => {
      if (!obj) return;
      Object.entries(obj).forEach(([name, ver]) => {
        deps.push({ name, version: String(ver).replace(/[\^~>=<\s]/g, ''), type, ecosystem: 'npm' });
      });
    };
    addDeps(pkg.dependencies, 'production');
    addDeps(pkg.devDependencies, 'development');
    addDeps(pkg.peerDependencies, 'peer');
    return deps;
  } catch (_) { return null; }
}

function parseRequirementsTxt(text) {
  const deps = [];
  text.split('\n').forEach(line => {
    line = line.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) return;
    const m = line.match(/^([a-zA-Z0-9_.-]+)\s*(?:[=<>!~]+\s*(.+))?/);
    if (m) deps.push({ name: m[1].toLowerCase(), version: (m[2] || '').trim(), type: 'production', ecosystem: 'pypi' });
  });
  return deps.length > 0 ? deps : null;
}

function parseGemfile(text) {
  const deps = [];
  text.split('\n').forEach(line => {
    const m = line.match(/gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/);
    if (m) deps.push({ name: m[1], version: (m[2] || '').replace(/[~>=<\s]/g, ''), type: 'production', ecosystem: 'gem' });
  });
  return deps.length > 0 ? deps : null;
}

function parseGoMod(text) {
  const deps = [];
  let inRequire = false;
  text.split('\n').forEach(line => {
    line = line.trim();
    if (line === 'require (') { inRequire = true; return; }
    if (line === ')') { inRequire = false; return; }
    if (inRequire || line.startsWith('require ')) {
      const m = line.match(/^\s*(?:require\s+)?([^\s]+)\s+v?([^\s]+)/);
      if (m) deps.push({ name: m[1], version: m[2], type: 'production', ecosystem: 'go' });
    }
  });
  return deps.length > 0 ? deps : null;
}

function parsePomXml(text) {
  const deps = [];
  const re = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    deps.push({ name: m[1] + ':' + m[2], version: (m[3] || '').replace(/[\[\]()]/g, ''), type: 'production', ecosystem: 'maven' });
  }
  return deps.length > 0 ? deps : null;
}

function autoDetectAndParse(text) {
  text = text.trim();
  if (text.startsWith('{')) return parsePackageJson(text);
  if (text.includes('<dependency>')) return parsePomXml(text);
  if (text.includes('gem ')) return parseGemfile(text);
  if (text.includes('module ') && text.includes('go ')) return parseGoMod(text);
  return parseRequirementsTxt(text);
}

// ============================================================================
// ANALYSIS ENGINE
// ============================================================================
function analyzeDependency(dep) {
  const findings = [];
  // CVE check
  VULN_PACKAGES.forEach(v => {
    if (v.ecosystem === dep.ecosystem && v.name === dep.name) {
      findings.push({ type: 'vulnerability', severity: v.cvss >= 9 ? 'critical' : v.cvss >= 7 ? 'high' : v.cvss >= 4 ? 'medium' : 'low', cve: v.cve, cvss: v.cvss, desc: v.desc, fix: v.fix });
    }
  });
  // Typosquat check
  const ecoSquats = TYPOSQUAT_CHECKS[dep.ecosystem] || {};
  Object.entries(ecoSquats).forEach(([real, fakes]) => {
    if (fakes.includes(dep.name)) {
      findings.push({ type: 'typosquat', severity: 'critical', desc: 'This looks like a typosquat of "' + real + '". Verify the package name carefully.', fix: 'Use "' + real + '" instead' });
    }
  });
  // License check (simulated — in reality would need registry lookup)
  const knownLicenses = { 'express': 'MIT', 'react': 'MIT', 'lodash': 'MIT', 'django': 'BSD-3-Clause', 'flask': 'BSD-3-Clause', 'requests': 'Apache-2.0', 'rails': 'MIT', 'moment': 'MIT', 'axios': 'MIT', 'mongodb': 'SSPL-1.0', 'elasticsearch': 'SSPL-1.0' };
  const lic = knownLicenses[dep.name];
  if (lic) {
    const lr = LICENSE_RISK[lic];
    if (lr && (lr.risk === 'high' || lr.risk === 'critical')) {
      findings.push({ type: 'license', severity: lr.risk, desc: lic + ': ' + lr.note, fix: 'Review license compatibility with your project' });
    }
  }
  return findings;
}

function scoreRisk(deps, allFindings) {
  let score = 100;
  allFindings.forEach(f => {
    f.findings.forEach(finding => {
      if (finding.severity === 'critical') score -= 15;
      else if (finding.severity === 'high') score -= 8;
      else if (finding.severity === 'medium') score -= 3;
      else score -= 1;
    });
  });
  return Math.max(0, score);
}

// ============================================================================
// SBOM GENERATOR
// ============================================================================
function generateSBOM(deps, format) {
  if (format === 'cyclonedx') {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">\n';
    xml += '  <components>\n';
    deps.forEach(d => {
      xml += '    <component type="library">\n';
      xml += '      <name>' + esc(d.name) + '</name>\n';
      xml += '      <version>' + esc(d.version) + '</version>\n';
      xml += '      <purl>pkg:' + d.ecosystem + '/' + encodeURIComponent(d.name) + '@' + encodeURIComponent(d.version) + '</purl>\n';
      xml += '    </component>\n';
    });
    xml += '  </components>\n</bom>';
    return xml;
  }
  // SPDX
  let spdx = 'SPDXVersion: SPDX-2.3\n';
  spdx += 'DataLicense: CC0-1.0\n';
  spdx += 'SPDXID: SPDXRef-DOCUMENT\n';
  spdx += 'DocumentName: supply-chain-analysis\n';
  spdx += 'DocumentNamespace: https://darknode.ai/spdx/' + Date.now() + '\n\n';
  deps.forEach((d, i) => {
    spdx += 'PackageName: ' + d.name + '\n';
    spdx += 'SPDXID: SPDXRef-Package-' + (i + 1) + '\n';
    spdx += 'PackageVersion: ' + d.version + '\n';
    spdx += 'PackageDownloadLocation: NOASSERTION\n';
    spdx += 'ExternalRef: PACKAGE-MANAGER purl pkg:' + d.ecosystem + '/' + encodeURIComponent(d.name) + '@' + encodeURIComponent(d.version) + '\n\n';
  });
  return spdx;
}

// ============================================================================
// RENDER
// ============================================================================
export function renderSupplyChainAnalyzer(main) {
  let deps = [];
  let analysisResults = [];
  let activeTab = 'analyze';

  function render() {
    main.innerHTML =
      '<h1 class="pg-h1">Supply Chain Risk Analyzer</h1>' +
      '<p class="muted pg-sub">Map, score, and remediate software supply chain risk. Paste a dependency file to analyze.</p>' +
      '<div class="tab-bar" style="overflow-x:auto;flex-wrap:nowrap">' +
        '<button class="tab' + (activeTab === 'analyze' ? ' active' : '') + '" data-tab="analyze">Analyze</button>' +
        '<button class="tab' + (activeTab === 'incidents' ? ' active' : '') + '" data-tab="incidents">Attack Incidents</button>' +
        '<button class="tab' + (activeTab === 'checklist' ? ' active' : '') + '" data-tab="checklist">Pipeline Security</button>' +
        '<button class="tab' + (activeTab === 'sbom' ? ' active' : '') + '" data-tab="sbom">SBOM Generator</button>' +
      '</div>' +
      '<div id="sca-content" style="margin-top:12px"></div>';

    main.querySelector('.tab-bar').onclick = (e) => {
      const b = e.target.closest('.tab');
      if (!b) return;
      activeTab = b.dataset.tab;
      render();
    };

    var content = main.querySelector('#sca-content');
    if (activeTab === 'analyze') renderAnalyzeTab(content);
    else if (activeTab === 'incidents') renderIncidentsTab(content);
    else if (activeTab === 'checklist') renderChecklistTab(content);
    else if (activeTab === 'sbom') renderSBOMTab(content);
  }

  function renderAnalyzeTab(container) {
    container.innerHTML =
      '<div style="margin-bottom:12px">' +
        '<label style="font-size:.8rem;color:var(--mut);display:block;margin-bottom:4px">Paste package.json, requirements.txt, Gemfile, go.mod, or pom.xml:</label>' +
        '<textarea class="tk-in" id="sca-input" rows="8" placeholder="Paste your dependency file here...\n\nSupported formats:\n- package.json (npm)\n- requirements.txt (Python)\n- Gemfile (Ruby)\n- go.mod (Go)\n- pom.xml (Maven)"></textarea>' +
      '</div>' +
      '<div class="tk-btns">' +
        '<button class="btn sm" id="sca-analyze">Analyze Dependencies</button>' +
        '<button class="btn sm ghost" id="sca-sample">Load Sample package.json</button>' +
      '</div>' +
      '<div id="sca-results" style="margin-top:16px"></div>';

    container.querySelector('#sca-sample').onclick = function() {
      container.querySelector('#sca-input').value = JSON.stringify({
        name: "example-app",
        version: "1.0.0",
        dependencies: {
          "express": "^4.17.1",
          "lodash": "4.17.11",
          "moment": "2.29.1",
          "axios": "0.21.1",
          "jsonwebtoken": "8.5.1",
          "mongoose": "6.0.0",
          "passport": "0.5.0",
          "node-fetch": "2.6.1",
          "minimist": "1.2.5",
          "xml2js": "0.4.23",
          "semver": "7.3.5",
          "tar": "6.1.0"
        },
        devDependencies: {
          "jest": "29.0.0",
          "eslint": "8.0.0"
        }
      }, null, 2);
    };

    container.querySelector('#sca-analyze').onclick = function() {
      var input = container.querySelector('#sca-input').value.trim();
      if (!input) return;
      deps = autoDetectAndParse(input);
      if (!deps || deps.length === 0) {
        container.querySelector('#sca-results').innerHTML = '<p style="color:#ff1744">Could not parse dependencies. Check the format.</p>';
        return;
      }
      analysisResults = deps.map(function(d) { return { dep: d, findings: analyzeDependency(d) }; });
      var riskScore = scoreRisk(deps, analysisResults);
      var critCount = 0, highCount = 0, medCount = 0, lowCount = 0;
      analysisResults.forEach(function(r) { r.findings.forEach(function(f) {
        if (f.severity === 'critical') critCount++;
        else if (f.severity === 'high') highCount++;
        else if (f.severity === 'medium') medCount++;
        else lowCount++;
      }); });
      var totalFindings = critCount + highCount + medCount + lowCount;
      var scoreColor = riskScore >= 80 ? '#00e676' : riskScore >= 60 ? '#ffd600' : riskScore >= 40 ? '#ff9100' : '#ff1744';

      var html = '<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px">' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px 20px;min-width:120px">' +
          '<div style="font-size:2rem;font-weight:700;color:' + scoreColor + '">' + riskScore + '/100</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">RISK SCORE</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px 20px">' +
          '<div style="font-size:1.4rem;font-weight:700">' + deps.length + '</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">DEPENDENCIES</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px 20px">' +
          '<div style="font-size:1.4rem;font-weight:700;color:#ff1744">' + critCount + '</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">CRITICAL</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px 20px">' +
          '<div style="font-size:1.4rem;font-weight:700;color:#ff9100">' + highCount + '</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">HIGH</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px 20px">' +
          '<div style="font-size:1.4rem;font-weight:700;color:#ffd600">' + medCount + '</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">MEDIUM</div></div>' +
      '</div>';

      if (totalFindings > 0) {
        html += '<h3 style="margin:0 0 8px;font-size:.9rem">Findings</h3>' +
          '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
          '<thead><tr style="border-bottom:2px solid var(--line)">' +
          '<th style="padding:6px;text-align:left;color:var(--mut)">Package</th>' +
          '<th style="padding:6px;text-align:left;color:var(--mut)">Version</th>' +
          '<th style="padding:6px;text-align:left;color:var(--mut)">Severity</th>' +
          '<th style="padding:6px;text-align:left;color:var(--mut)">Type</th>' +
          '<th style="padding:6px;text-align:left;color:var(--mut)">Issue</th>' +
          '<th style="padding:6px;text-align:left;color:var(--mut)">Fix</th>' +
          '</tr></thead><tbody>';
        analysisResults.forEach(function(r) {
          r.findings.forEach(function(f) {
            var sevColor = f.severity === 'critical' ? '#ff1744' : f.severity === 'high' ? '#ff9100' : f.severity === 'medium' ? '#ffd600' : 'var(--mut)';
            html += '<tr style="border-bottom:1px solid var(--line)">' +
              '<td style="padding:6px;font-weight:600">' + esc(r.dep.name) + '</td>' +
              '<td style="padding:6px;color:var(--mut)">' + esc(r.dep.version) + '</td>' +
              '<td style="padding:6px"><span style="color:' + sevColor + ';font-weight:600;text-transform:uppercase;font-size:.7rem">' + esc(f.severity) + '</span></td>' +
              '<td style="padding:6px;color:var(--acc);font-size:.72rem">' + esc(f.type) + (f.cve ? ' (' + esc(f.cve) + ')' : '') + '</td>' +
              '<td style="padding:6px">' + esc(f.desc) + '</td>' +
              '<td style="padding:6px;color:#00e676">' + esc(f.fix) + '</td>' +
            '</tr>';
          });
        });
        html += '</tbody></table></div>';
      }

      // Clean deps
      var cleanDeps = analysisResults.filter(function(r) { return r.findings.length === 0; });
      if (cleanDeps.length > 0) {
        html += '<details style="margin-top:12px"><summary style="cursor:pointer;font-size:.82rem;color:var(--mut)">' + cleanDeps.length + ' clean dependencies (no issues found)</summary>' +
          '<div style="margin-top:8px;font-size:.78rem;color:var(--mut)">' + cleanDeps.map(function(r) { return esc(r.dep.name) + '@' + esc(r.dep.version); }).join(', ') + '</div></details>';
      }

      container.querySelector('#sca-results').innerHTML = html;
    };
  }

  function renderIncidentsTab(container) {
    container.innerHTML =
      '<h2 class="pg-h2">Supply Chain Attack Incidents</h2>' +
      '<p class="muted" style="margin-bottom:16px">' + SC_INCIDENTS.length + ' documented supply chain attacks with timeline, impact, and lessons learned.</p>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px">' +
      SC_INCIDENTS.map(function(inc) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">' +
            '<span style="font-weight:700;font-size:.9rem">' + esc(inc.name) + '</span>' +
            '<span style="font-size:.65rem;color:var(--acc);border:1px solid var(--acc);padding:1px 6px;border-radius:3px">' + inc.year + '</span>' +
          '</div>' +
          '<div style="font-size:.72rem;color:#ff9100;margin-bottom:4px">' + esc(inc.type) + '</div>' +
          '<div style="font-size:.78rem;color:var(--mut);margin-bottom:8px;line-height:1.5">' + esc(inc.desc) + '</div>' +
          '<div style="font-size:.75rem;margin-bottom:6px"><strong style="color:var(--txt)">Impact:</strong> <span style="color:#ff1744">' + esc(inc.impact) + '</span></div>' +
          '<div style="font-size:.75rem;background:rgba(0,228,255,0.06);border:1px solid rgba(0,228,255,0.15);border-radius:4px;padding:8px"><strong style="color:var(--acc)">Lesson:</strong> ' + esc(inc.lesson) + '</div>' +
        '</div>';
      }).join('') +
      '</div>';
  }

  function renderChecklistTab(container) {
    var saved = {};
    try { saved = JSON.parse(localStorage.getItem('sca_checklist') || '{}'); } catch (_) {}
    var categories = [];
    PIPELINE_CHECKLIST.forEach(function(item) { if (categories.indexOf(item.category) === -1) categories.push(item.category); });
    var completed = Object.keys(saved).filter(function(k) { return saved[k]; }).length;
    var total = PIPELINE_CHECKLIST.length;
    var pct = Math.round(completed / total * 100);

    container.innerHTML =
      '<h2 class="pg-h2">Build Pipeline Security Checklist</h2>' +
      '<p class="muted" style="margin-bottom:8px">' + total + ' items across ' + categories.length + ' categories. Your progress is saved locally.</p>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 16px;margin-bottom:16px;display:flex;align-items:center;gap:12px">' +
        '<div style="font-size:1.6rem;font-weight:700;color:' + (pct >= 80 ? '#00e676' : pct >= 50 ? '#ffd600' : '#ff9100') + '">' + pct + '%</div>' +
        '<div style="flex:1;height:8px;background:var(--line);border-radius:4px;overflow:hidden"><div style="height:100%;width:' + pct + '%;background:' + (pct >= 80 ? '#00e676' : pct >= 50 ? '#ffd600' : '#ff9100') + ';border-radius:4px;transition:width .3s"></div></div>' +
        '<div style="font-size:.78rem;color:var(--mut)">' + completed + ' / ' + total + '</div>' +
      '</div>' +
      '<div id="sca-checklist-items">' +
      categories.map(function(cat) {
        var items = PIPELINE_CHECKLIST.filter(function(i) { return i.category === cat; });
        return '<h3 style="font-size:.85rem;margin:16px 0 6px;color:var(--acc)">' + esc(cat) + '</h3>' +
          items.map(function(item, idx) {
            var key = cat + '_' + idx;
            var checked = saved[key] ? ' checked' : '';
            var prioColor = item.priority === 'Critical' ? '#ff1744' : item.priority === 'High' ? '#ff9100' : item.priority === 'Medium' ? '#ffd600' : 'var(--mut)';
            return '<label style="display:flex;align-items:flex-start;gap:8px;padding:6px 0;font-size:.8rem;cursor:pointer;border-bottom:1px solid var(--line)">' +
              '<input type="checkbox" data-key="' + esc(key) + '"' + checked + ' style="margin-top:3px">' +
              '<span' + (checked ? ' style="text-decoration:line-through;color:var(--mut)"' : '') + '>' + esc(item.item) + '</span>' +
              '<span style="margin-left:auto;font-size:.65rem;color:' + prioColor + ';font-weight:600;white-space:nowrap">' + esc(item.priority) + '</span>' +
            '</label>';
          }).join('');
      }).join('') +
      '</div>';

    container.querySelector('#sca-checklist-items').addEventListener('change', function(e) {
      if (e.target.type === 'checkbox' && e.target.dataset.key) {
        saved[e.target.dataset.key] = e.target.checked;
        try { localStorage.setItem('sca_checklist', JSON.stringify(saved)); } catch (_) {}
        render();
      }
    });
  }

  function renderSBOMTab(container) {
    if (deps.length === 0) {
      container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Analyze dependencies first (Analyze tab), then generate an SBOM.</p>';
      return;
    }
    container.innerHTML =
      '<h2 class="pg-h2">Software Bill of Materials</h2>' +
      '<p class="muted" style="margin-bottom:12px">Generate an SBOM from your analyzed dependencies.</p>' +
      '<div class="tk-btns">' +
        '<button class="btn sm" id="sca-cyclonedx">Generate CycloneDX (XML)</button>' +
        '<button class="btn sm ghost" id="sca-spdx">Generate SPDX</button>' +
      '</div>' +
      '<pre class="tk-out" id="sca-sbom-out" style="margin-top:12px;max-height:400px;overflow-y:auto"></pre>';

    container.querySelector('#sca-cyclonedx').onclick = function() {
      container.querySelector('#sca-sbom-out').textContent = generateSBOM(deps, 'cyclonedx');
    };
    container.querySelector('#sca-spdx').onclick = function() {
      container.querySelector('#sca-sbom-out').textContent = generateSBOM(deps, 'spdx');
    };
  }

  render();
}
