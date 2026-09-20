// Copyright (c) 2026 SpartanKing18. All rights reserved.
// CI/CD Pipeline Security Reference — GitHub Actions, GitLab CI, Jenkins, supply chain attacks.

export const GITHUB_ACTIONS_SECURITY = {
  description: "GitHub Actions is the most popular CI/CD platform. Security risks include secret exposure, malicious actions, and workflow injection.",
  vulnerabilities: [
    { id: "GHA-001", title: "Workflow injection via issue title/body", severity: "critical", description: "Using ${{ github.event.issue.title }} or ${{ github.event.pull_request.body }} directly in a run: step allows code injection. An attacker can craft an issue title containing shell commands.", example_vulnerable: "run: echo 'Processing: ${{ github.event.issue.title }}'", example_secure: "env:\n  TITLE: ${{ github.event.issue.title }}\nrun: echo \"Processing: $TITLE\"", cwe: "CWE-78" },
    { id: "GHA-002", title: "pull_request_target with checkout", severity: "critical", description: "Workflows triggered by pull_request_target run with the base repo's secrets. If they check out the PR code and run it, a malicious PR can steal secrets.", example_vulnerable: "on: pull_request_target\nsteps:\n  - uses: actions/checkout@v4\n    with:\n      ref: ${{ github.event.pull_request.head.sha }}", example_secure: "on: pull_request # runs with PR fork's limited permissions instead", cwe: "CWE-829" },
    { id: "GHA-003", title: "Unpinned third-party actions", severity: "high", description: "Using actions with @main or @v1 (mutable tag) allows the action author to inject malicious code that runs with your repo's secrets.", example_vulnerable: "uses: someorg/action@main", example_secure: "uses: someorg/action@abc123def456 # pinned to commit SHA", cwe: "CWE-829" },
    { id: "GHA-004", title: "Excessive GITHUB_TOKEN permissions", severity: "high", description: "Default GITHUB_TOKEN permissions may be too broad (write access to all scopes). Workflows should use least privilege.", example_vulnerable: "# No permissions block = default permissions (often write-all)", example_secure: "permissions:\n  contents: read\n  pull-requests: write", cwe: "CWE-269" },
    { id: "GHA-005", title: "Secrets in logs", severity: "high", description: "GitHub automatically masks secrets in logs, but base64-encoded, reversed, or split secrets can leak.", example_vulnerable: "run: echo ${{ secrets.API_KEY }} | base64", example_secure: "run: echo '::add-mask::$ENCODED_SECRET'", cwe: "CWE-532" },
    { id: "GHA-006", title: "Self-hosted runner persistence", severity: "critical", description: "Self-hosted runners persist between jobs. A malicious workflow can plant backdoors, steal cached credentials, or modify tools.", example_vulnerable: "runs-on: self-hosted # shared, non-ephemeral runner", example_secure: "runs-on: self-hosted # ephemeral runner with --ephemeral flag, or use GitHub-hosted runners", cwe: "CWE-502" },
    { id: "GHA-007", title: "OIDC token with broad audience", severity: "medium", description: "Overly permissive OIDC token audience or subject claims allow any workflow to authenticate to cloud providers.", example_vulnerable: "trust policy: sub = repo:org/*:*", example_secure: "trust policy: sub = repo:org/repo:ref:refs/heads/main # specific repo and branch", cwe: "CWE-287" },
    { id: "GHA-008", title: "Artifact poisoning", severity: "high", description: "Artifacts uploaded by one job can be tampered with before being downloaded by another job in a different workflow.", example_vulnerable: "Download artifact from untrusted workflow without verification", example_secure: "Verify artifact checksums. Use OIDC-signed attestations.", cwe: "CWE-345" },
    { id: "GHA-009", title: "Cache poisoning", severity: "high", description: "Malicious PR workflows can poison the GitHub Actions cache, affecting subsequent runs on the default branch.", example_vulnerable: "actions/cache with key that can be set by PR", example_secure: "Use immutable cache keys based on lockfile hashes. Validate cached content.", cwe: "CWE-345" },
    { id: "GHA-010", title: "Workflow_dispatch with unchecked inputs", severity: "medium", description: "Workflow dispatch inputs used directly in run: steps allow injection similar to issue title injection.", example_vulnerable: "run: deploy ${{ github.event.inputs.environment }}", example_secure: "Use choice type inputs or validate against allowlist", cwe: "CWE-78" }
  ],
  hardening: [
    "Set default GITHUB_TOKEN permissions to read-only at the org level",
    "Pin all third-party actions to full commit SHAs",
    "Use Dependabot to keep actions updated",
    "Never use pull_request_target with PR code checkout",
    "Use environment protection rules for deployments",
    "Use OIDC for cloud authentication instead of long-lived secrets",
    "Restrict self-hosted runners to private repos with ephemeral flag",
    "Enable required reviewers for workflow file changes",
    "Use branch protection rules on main/production branches",
    "Enable secret scanning and push protection",
    "Use CodeQL for static analysis in CI",
    "Implement OpenSSF Scorecard checks"
  ]
};

export const GITLAB_CI_SECURITY = {
  description: "GitLab CI/CD security considerations for pipelines, runners, and configuration.",
  vulnerabilities: [
    { id: "GL-001", title: "Shared runners with untrusted code", severity: "high", description: "Shared runners process jobs from multiple projects. A malicious job can attempt to access secrets or attack the runner.", remediation: "Use project-specific runners for sensitive workloads. Enable runner isolation." },
    { id: "GL-002", title: "Variable masking bypassed", severity: "high", description: "Protected variables can be logged if manipulated (base64, split, reversed). GitLab's masking is pattern-based.", remediation: "Mark variables as protected and masked. Review pipeline logs for leaks." },
    { id: "GL-003", title: "Unprotected CI/CD variables", severity: "critical", description: "Variables not marked as 'protected' are available to all branches, including feature branches from contributors.", remediation: "Mark sensitive variables as protected. Restrict to specific branches/tags." },
    { id: "GL-004", title: "Pipeline trigger token leaked", severity: "critical", description: "Pipeline trigger tokens allow anyone to start pipelines. If leaked, attackers can execute arbitrary pipeline code.", remediation: "Rotate trigger tokens regularly. Use IP restrictions." },
    { id: "GL-005", title: "Include from external sources", severity: "high", description: "Using include: remote in .gitlab-ci.yml loads pipeline definitions from external URLs, which can be modified.", remediation: "Include from trusted internal projects. Pin to specific refs." },
    { id: "GL-006", title: "Merge request pipelines run untrusted code", severity: "high", description: "Pipelines triggered by merge requests execute code from the source branch, which may be from a fork.", remediation: "Restrict fork pipelines. Don't expose secrets to fork MR pipelines." },
    { id: "GL-007", title: "Artifact expiration not set", severity: "low", description: "Artifacts without expiration consume storage and may contain sensitive data accessible indefinitely.", remediation: "Set expire_in on all artifacts. Default to 30 days." },
    { id: "GL-008", title: "No SAST/DAST in pipeline", severity: "medium", description: "Without security scanning in the pipeline, vulnerabilities reach production undetected.", remediation: "Enable GitLab SAST, DAST, dependency scanning, and container scanning templates." }
  ],
  hardening: [
    "Use project-specific runners for sensitive projects",
    "Mark all secrets as protected and masked variables",
    "Enable merge request approvals for .gitlab-ci.yml changes",
    "Restrict fork pipeline execution",
    "Use include: project instead of include: remote",
    "Enable SAST, DAST, dependency scanning, and secret detection",
    "Set artifact expiration",
    "Use protected branches and tags",
    "Enable pipeline security policies",
    "Review runner registration tokens periodically"
  ]
};

export const JENKINS_SECURITY = {
  description: "Jenkins security is critical because it often has access to production credentials and deployment pipelines.",
  vulnerabilities: [
    { id: "JK-001", title: "Groovy sandbox escape", severity: "critical", description: "Jenkins Pipeline scripts run in a Groovy sandbox, but numerous sandbox escapes have been discovered allowing arbitrary code execution on the Jenkins master.", cves: ["CVE-2019-1003000", "CVE-2018-1000861", "CVE-2019-1003029"], remediation: "Keep Jenkins and plugins updated. Use declarative pipelines over scripted where possible." },
    { id: "JK-002", title: "Credentials stored in plaintext", severity: "critical", description: "Jenkins stores credentials encrypted, but the encryption key is on the filesystem. Anyone with file access can decrypt all credentials.", remediation: "Restrict filesystem access. Use external credential providers (HashiCorp Vault, CyberArk)." },
    { id: "JK-003", title: "No authentication on Jenkins", severity: "critical", description: "Jenkins with anonymous read or execute access allows anyone to view jobs, credentials, and trigger builds.", remediation: "Enable authentication. Integrate with LDAP/AD/SAML. Disable anonymous access." },
    { id: "JK-004", title: "Script Console accessible", severity: "critical", description: "Jenkins Script Console at /script allows executing arbitrary Groovy code with full Jenkins permissions.", remediation: "Restrict Script Console access to admins only. Monitor access logs." },
    { id: "JK-005", title: "Outdated plugins with known CVEs", severity: "high", description: "Jenkins plugin ecosystem has frequent security vulnerabilities. Outdated plugins are the #1 attack vector.", remediation: "Update plugins regularly. Remove unused plugins. Subscribe to Jenkins security advisories." },
    { id: "JK-006", title: "Agent-to-controller access not restricted", severity: "high", description: "Jenkins agents can access the controller's filesystem and APIs if agent-to-controller security is disabled.", remediation: "Enable Agent → Controller Access Control in Manage Jenkins > Security." },
    { id: "JK-007", title: "Builds triggered without authentication", severity: "high", description: "Remote build triggers without authentication tokens allow anyone to trigger builds.", remediation: "Require authentication tokens for remote triggers. Use webhook secrets." },
    { id: "JK-008", title: "JNLP agents with weak security", severity: "medium", description: "JNLP (Java Web Start) agents using TCP may be vulnerable to agent impersonation.", remediation: "Use SSH agents or WebSocket agents instead of JNLP. If JNLP is required, use the WebSocket protocol." }
  ],
  hardening: [
    "Enable authentication and authorization (Matrix-based or Role-based)",
    "Restrict Script Console to admin users only",
    "Keep Jenkins core and all plugins updated",
    "Enable CSRF protection (crumb issuer)",
    "Enable Agent → Controller Access Control",
    "Use SSH agents instead of JNLP",
    "Store credentials in external vaults (HashiCorp Vault integration)",
    "Run Jenkins behind a reverse proxy with TLS",
    "Enable audit logging",
    "Use folder-level permissions for multi-team setups",
    "Disable CLI over remoting",
    "Run Jenkins master in a container with limited privileges"
  ]
};

export const SUPPLY_CHAIN_ATTACKS = [
  { name: "Dependency Confusion", description: "Attacker publishes a malicious package to a public registry (npm, PyPI) with the same name as a private/internal package. Build systems may prefer the public version if not configured correctly.", affected: ["npm", "pip", "NuGet", "RubyGems", "Maven"], mitigations: ["Use scoped packages (@company/package)", "Configure registry priorities", "Use lockfiles with integrity hashes", "Implement a private registry proxy"], notable_incidents: ["Alex Birsan's 2021 research affecting Apple, Microsoft, PayPal", "ua-parser-js npm package (2021)"] },
  { name: "Typosquatting", description: "Attacker publishes packages with names similar to popular packages (e.g., 'lodahs' instead of 'lodash') hoping developers will install them by mistake.", affected: ["npm", "PyPI", "RubyGems"], mitigations: ["Review package names carefully", "Use lockfiles", "Enable npm audit", "Use tools like socket.dev"], notable_incidents: ["crossenv npm package (2017)", "python3-dateutil PyPI (2019)", "colors/faker npm sabotage (2022)"] },
  { name: "Compromised Maintainer Account", description: "Attacker gains access to a package maintainer's account and publishes a malicious version of a legitimate package.", affected: ["All registries"], mitigations: ["Require 2FA for maintainers", "Review new version changes", "Pin dependencies to specific versions", "Use lockfiles with hashes"], notable_incidents: ["event-stream npm (2018)", "ua-parser-js npm (2021)", "coa npm (2021)"] },
  { name: "Malicious GitHub Action / CI Plugin", description: "Attacker creates or compromises a GitHub Action, GitLab CI template, or Jenkins plugin that exfiltrates secrets during CI runs.", affected: ["GitHub Actions", "GitLab CI", "Jenkins"], mitigations: ["Pin actions to commit SHAs", "Audit action source code", "Use only verified/official actions", "Restrict GITHUB_TOKEN permissions"], notable_incidents: ["Codecov Bash Uploader (2021)", "GitHub Actions tj-actions/changed-files (2025)"] },
  { name: "Compromised Build Infrastructure", description: "Attacker compromises the build server, CI runner, or artifact repository to inject malicious code into legitimate software releases.", affected: ["All CI/CD systems"], mitigations: ["Use ephemeral build environments", "Implement reproducible builds", "Sign artifacts", "Monitor build logs for anomalies"], notable_incidents: ["SolarWinds (2020)", "Kaseya VSA (2021)", "3CX (2023)", "XZ Utils (2024)"] },
  { name: "Protestware / Self-Sabotage", description: "A maintainer intentionally adds destructive or political code to their own package, affecting all users.", affected: ["All registries"], mitigations: ["Pin dependencies", "Review changelogs before updating", "Use tools that detect behavioral changes", "Maintain internal forks of critical dependencies"], notable_incidents: ["colors.js infinite loop (2022)", "node-ipc geo-based file wipe (2022)", "faker.js deletion (2022)"] }
];

export const SAST_DAST_TOOLS = [
  { name: "Semgrep", type: "SAST", description: "Fast, lightweight static analysis with custom rules. Supports 30+ languages. Free tier available.", languages: ["Python", "JavaScript", "TypeScript", "Java", "Go", "Ruby", "C", "C++", "PHP", "Rust", "Kotlin", "Swift"], ci_integration: "semgrep ci --config=auto" },
  { name: "CodeQL", type: "SAST", description: "GitHub's semantic code analysis engine. Treats code as data, queries for vulnerability patterns. Free for open source.", languages: ["C/C++", "C#", "Go", "Java", "JavaScript", "Python", "Ruby", "Swift"], ci_integration: "github/codeql-action/analyze@v3" },
  { name: "SonarQube", type: "SAST", description: "Comprehensive code quality and security platform. Self-hosted or cloud (SonarCloud). Detects bugs, vulnerabilities, code smells.", languages: ["27+ languages"], ci_integration: "sonar-scanner -Dsonar.projectKey=KEY" },
  { name: "Bandit", type: "SAST", description: "Python-specific security linter. Finds common security issues like SQL injection, hardcoded passwords, and insecure crypto.", languages: ["Python"], ci_integration: "bandit -r ./src -f json -o bandit-results.json" },
  { name: "Brakeman", type: "SAST", description: "Static analysis specifically for Ruby on Rails applications. Detects SQL injection, XSS, and Rails-specific vulnerabilities.", languages: ["Ruby (Rails)"], ci_integration: "brakeman -o brakeman-output.json" },
  { name: "ESLint Security", type: "SAST", description: "ESLint plugin for detecting security issues in JavaScript/TypeScript code.", languages: ["JavaScript", "TypeScript"], ci_integration: "eslint --plugin security --ext .js,.ts src/" },
  { name: "OWASP ZAP", type: "DAST", description: "Open-source web application security scanner. Automated scanning for OWASP Top 10 vulnerabilities.", target: "Web applications", ci_integration: "docker run -v $(pwd):/zap/wrk owasp/zap2docker-stable zap-baseline.py -t https://app.example.com" },
  { name: "Nuclei", type: "DAST", description: "Fast, template-based vulnerability scanner with 7000+ templates for CVEs, misconfigurations, and exposures.", target: "Web applications, APIs, infrastructure", ci_integration: "nuclei -u https://app.example.com -t cves/ -severity critical,high" },
  { name: "Snyk", type: "SCA", description: "Software Composition Analysis. Scans dependencies for known vulnerabilities, provides fix PRs.", target: "Dependencies, containers, IaC", ci_integration: "snyk test --all-projects" },
  { name: "Dependabot", type: "SCA", description: "GitHub's built-in dependency update tool. Creates PRs to update vulnerable dependencies.", target: "Dependencies", ci_integration: "Configured via .github/dependabot.yml" },
  { name: "Renovate", type: "SCA", description: "Automated dependency update tool supporting all major package managers. More configurable than Dependabot.", target: "Dependencies", ci_integration: "Configured via renovate.json" },
  { name: "Trivy", type: "SCA + Container", description: "All-in-one scanner for vulnerabilities, misconfigurations, and secrets in containers, filesystems, and repos.", target: "Containers, repos, filesystems", ci_integration: "trivy image myapp:latest --severity CRITICAL,HIGH --exit-code 1" },
  { name: "Checkov", type: "IaC", description: "Static analysis for Infrastructure as Code. Scans Terraform, CloudFormation, Kubernetes, Docker, and ARM templates.", target: "IaC files", ci_integration: "checkov -d . --framework terraform" },
  { name: "tfsec", type: "IaC", description: "Terraform-specific security scanner. Detects misconfigurations in Terraform code before deployment.", target: "Terraform files", ci_integration: "tfsec . --format json" },
  { name: "Gitleaks", type: "Secret", description: "Scans git repos for hardcoded secrets and credentials using regex and entropy analysis.", target: "Git repositories", ci_integration: "gitleaks detect --source . --report-format json" },
  { name: "TruffleHog", type: "Secret", description: "Searches git repos for high-entropy strings and known credential patterns across entire git history.", target: "Git repositories", ci_integration: "trufflehog git file://. --only-verified" },
  { name: "detect-secrets", type: "Secret", description: "Yelp's tool for detecting secrets in code. Uses a baseline file to track known secrets and detect new ones.", target: "Code files", ci_integration: "detect-secrets scan > .secrets.baseline" }
];

export const ARTIFACT_SIGNING = {
  description: "Signing build artifacts ensures integrity and provenance — that the artifact was built from trusted code by an authorized pipeline.",
  tools: [
    { name: "Sigstore / Cosign", description: "Keyless signing using OIDC identity (GitHub Actions, GitLab CI). Signs container images with transparency log (Rekor).", usage: "cosign sign --yes myregistry.io/myapp:sha-abc123" },
    { name: "Notation (Notary v2)", description: "OCI-standard signing for container images. Used by AWS Signer, Azure, and other cloud providers.", usage: "notation sign myregistry.io/myapp:latest --key KEY" },
    { name: "in-toto", description: "Framework for securing the software supply chain. Defines and verifies the steps in a build pipeline.", usage: "in-toto-run --step-name build -- make" },
    { name: "SLSA (Supply chain Levels for Software Artifacts)", description: "Framework of increasing security guarantees for software supply chains. Levels 1-4.", levels: [
      { level: 1, requirement: "Provenance exists — build process is documented" },
      { level: 2, requirement: "Hosted build — build runs on a hosted service with signed provenance" },
      { level: 3, requirement: "Hardened builds — builds are isolated, use hermetic and reproducible processes" },
      { level: 4, requirement: "Two-person review — all changes require independent review" }
    ]}
  ],
  github_actions_example: `name: Build and Sign
on: push
permissions:
  id-token: write
  contents: read
  packages: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sigstore/cosign-installer@v3
      - run: |
          docker build -t ghcr.io/ORG/APP:\${{ github.sha }} .
          docker push ghcr.io/ORG/APP:\${{ github.sha }}
          cosign sign --yes ghcr.io/ORG/APP:\${{ github.sha }}`
};

export const PIPELINE_HARDENING_CHECKLIST = [
  { category: "Secrets Management", checks: [
    "All secrets stored in CI/CD secret management (not in code)",
    "Secrets rotated on regular schedule",
    "No secrets logged or echoed in pipeline output",
    "OIDC used for cloud authentication instead of long-lived credentials",
    "Secrets scoped to specific branches/environments where possible"
  ]},
  { category: "Access Control", checks: [
    "Branch protection rules on main/production branches",
    "Required code reviews before merge",
    "Pipeline configuration changes require review",
    "Self-hosted runners restricted to trusted repositories",
    "Deployment environments have required reviewers"
  ]},
  { category: "Dependency Security", checks: [
    "Dependency scanning (SCA) in every pipeline",
    "Lockfiles committed and used in CI",
    "Dependencies pinned to specific versions with hashes",
    "Automated dependency updates (Dependabot/Renovate)",
    "Private registry proxy for public packages"
  ]},
  { category: "Build Security", checks: [
    "Third-party actions/plugins pinned to commit SHAs",
    "Minimal pipeline permissions (least privilege)",
    "Build artifacts signed with Sigstore or equivalent",
    "SBOM generated for every release",
    "Reproducible builds where possible"
  ]},
  { category: "Security Scanning", checks: [
    "SAST scanning in every PR pipeline",
    "Secret scanning with pre-commit hooks and CI",
    "Container image scanning before deployment",
    "IaC scanning (Checkov/tfsec) for infrastructure changes",
    "DAST scanning against staging environments"
  ]},
  { category: "Monitoring", checks: [
    "Pipeline execution logs retained and monitored",
    "Alerts on failed security scans",
    "Alerts on new dependency vulnerabilities",
    "Audit log for secret access and pipeline modifications",
    "Supply chain security score tracked (OpenSSF Scorecard)"
  ]}
];
