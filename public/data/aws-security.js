// Copyright (c) 2026 SpartanKing18. All rights reserved.
// AWS Security Reference — comprehensive coverage of AWS security services,
// misconfigurations, attack techniques, and hardening for authorized testing.

export const AWS_SERVICES = [
  {
    service: "IAM",
    fullName: "Identity and Access Management",
    description: "Central identity and access management for all AWS services. Controls who can do what across the entire AWS account.",
    misconfigurations: [
      { id: "IAM-001", title: "Root account used for daily operations", severity: "critical", description: "The root account has unrestricted access and cannot be limited by IAM policies. Using it for daily tasks violates least privilege.", detection: "aws iam get-account-summary | grep AccountMFAEnabled", remediation: "Create IAM users/roles for all operations. Enable MFA on root. Lock root access keys." },
      { id: "IAM-002", title: "No MFA on privileged accounts", severity: "critical", description: "IAM users with administrative privileges lack multi-factor authentication, allowing password-only access to critical operations.", detection: "aws iam list-users --query 'Users[*].UserName' | xargs -I{} aws iam list-mfa-devices --user-name {}", remediation: "Enforce MFA via IAM policy condition: aws:MultiFactorAuthPresent." },
      { id: "IAM-003", title: "Overly permissive IAM policies", severity: "high", description: "Policies with Action: '*' and Resource: '*' grant god-mode access. Even managed policies like AdministratorAccess should be tightly scoped.", detection: "aws iam list-policies --only-attached --query 'Policies[*].Arn' | xargs -I{} aws iam get-policy-version --policy-arn {} --version-id v1", remediation: "Use least-privilege policies. AWS Access Analyzer can generate scoped policies from CloudTrail logs." },
      { id: "IAM-004", title: "Long-lived access keys without rotation", severity: "high", description: "Static access keys that haven't been rotated in 90+ days increase the window for credential theft and abuse.", detection: "aws iam generate-credential-report && aws iam get-credential-report --query 'Content' --output text | base64 -d", remediation: "Rotate keys every 90 days. Prefer IAM roles with temporary credentials over long-lived keys." },
      { id: "IAM-005", title: "Inactive IAM users not removed", severity: "medium", description: "Accounts that haven't been used in 90+ days represent unnecessary attack surface. Dormant accounts are prime targets for credential stuffing.", detection: "aws iam generate-credential-report # check password_last_used and access_key_last_used columns", remediation: "Disable or delete users inactive for 90+ days. Automate with AWS Config rule: iam-user-unused-credentials-check." },
      { id: "IAM-006", title: "IAM policies attached directly to users", severity: "medium", description: "Policies should be attached to groups or roles, not individual users. Direct attachment makes auditing and management difficult at scale.", detection: "aws iam list-users --query 'Users[*].UserName' | xargs -I{} aws iam list-attached-user-policies --user-name {}", remediation: "Create IAM groups with appropriate policies. Add users to groups instead of attaching policies directly." },
      { id: "IAM-007", title: "Cross-account role trust too broad", severity: "high", description: "AssumeRole trust policies with Principal: '*' or overly broad account IDs allow any AWS account to assume the role.", detection: "aws iam list-roles --query 'Roles[*].RoleName' | xargs -I{} aws iam get-role --role-name {} --query 'Role.AssumeRolePolicyDocument'", remediation: "Restrict Principal to specific account IDs and add ExternalId condition for third-party access." },
      { id: "IAM-008", title: "Wildcard permissions in resource policies", severity: "high", description: "Resource-based policies (S3 bucket policies, KMS key policies, SQS policies) with Principal: '*' expose resources to the public or any authenticated AWS user.", detection: "aws s3api get-bucket-policy --bucket BUCKET_NAME", remediation: "Replace wildcards with specific account IDs, IAM users, or roles. Use aws:SourceAccount conditions." },
      { id: "IAM-009", title: "PassRole without resource constraint", severity: "high", description: "iam:PassRole with Resource: '*' lets a user pass any role to any service, enabling privilege escalation by passing an admin role to a Lambda or EC2 instance.", detection: "Search all policies for 'iam:PassRole' with Resource '*'", remediation: "Constrain PassRole to specific role ARNs that the user legitimately needs to assign." },
      { id: "IAM-010", title: "No permissions boundary on delegated admins", severity: "medium", description: "IAM users who can create other users/roles without a permissions boundary can create entities with more privileges than they themselves have.", detection: "Check if iam:CreateRole and iam:CreateUser actions require iam:PermissionsBoundary condition", remediation: "Enforce permissions boundaries via SCP or IAM policy conditions for any identity that can create other identities." },
      { id: "IAM-011", title: "SAML/OIDC federation misconfigured", severity: "high", description: "Overly permissive trust policies on SAML or OIDC identity providers can allow any user from the federated IdP to assume roles.", detection: "aws iam list-saml-providers && aws iam list-open-id-connect-providers", remediation: "Add conditions on SAML:aud, SAML:sub, or token.actions.githubusercontent.com:sub to restrict federated access." },
      { id: "IAM-012", title: "Service-linked roles with excessive scope", severity: "medium", description: "AWS-managed service-linked roles sometimes have broader permissions than necessary for the service's operation.", detection: "aws iam list-roles --query 'Roles[?starts_with(Path, `/aws-service-role/`)]'", remediation: "Review service-linked role policies periodically. Use SCPs to deny unused service actions." }
    ],
    attacks: [
      { name: "Privilege escalation via PassRole + Lambda", description: "Attacker with iam:PassRole and lambda:CreateFunction can create a Lambda with an admin role, then invoke it to perform any action.", mitre: "T1078.004", steps: ["Create Lambda function with admin execution role", "Write function code that creates new admin user", "Invoke the function", "Login as new admin user"] },
      { name: "Privilege escalation via CreatePolicyVersion", description: "User with iam:CreatePolicyVersion can create a new version of any managed policy and set it as default, granting themselves any permissions.", mitre: "T1098", steps: ["Identify attached managed policy ARN", "Create new policy version with Action:* Resource:*", "Set new version as default"] },
      { name: "Privilege escalation via UpdateAssumeRolePolicy", description: "Modify a high-privilege role's trust policy to allow the attacker to assume it.", mitre: "T1098", steps: ["Identify admin role", "Update trust policy to include attacker's ARN", "Assume the role with sts:AssumeRole"] },
      { name: "Credential theft via EC2 metadata service", description: "SSRF vulnerability in an EC2 application can be used to query the instance metadata service and steal IAM role credentials.", mitre: "T1552.005", steps: ["Find SSRF vulnerability", "Request http://169.254.169.254/latest/meta-data/iam/security-credentials/", "Get role name, then fetch temporary credentials", "Use credentials externally"] }
    ],
    hardening: [
      "Enable MFA for all IAM users, especially those with console access",
      "Use IAM Access Analyzer to identify unused permissions and refine policies",
      "Implement SCPs at the Organization level to set guardrails",
      "Enforce permissions boundaries for delegated administrators",
      "Use aws:SourceIp and aws:MultiFactorAuthPresent conditions",
      "Enable CloudTrail for IAM API logging in all regions",
      "Rotate access keys every 90 days; prefer roles over keys",
      "Use IAM Roles Anywhere for on-premises workloads instead of long-lived keys",
      "Tag all IAM resources for cost allocation and access control",
      "Review the credential report monthly for inactive users and unrotated keys"
    ],
    auditCommands: [
      "aws iam generate-credential-report",
      "aws iam get-credential-report --query Content --output text | base64 -d | csvtool col 1,4,5,9,11,14,16 -",
      "aws iam get-account-authorization-details --output json > iam-full-dump.json",
      "aws iam list-users --query 'Users[?PasswordLastUsed==null]'",
      "aws iam list-access-keys --user-name USERNAME",
      "aws iam list-attached-user-policies --user-name USERNAME",
      "aws iam list-user-policies --user-name USERNAME",
      "aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::ACCOUNT:user/USER --action-names s3:GetObject --resource-arns arn:aws:s3:::bucket/*",
      "aws accessanalyzer list-findings --analyzer-arn ANALYZER_ARN"
    ]
  },
  {
    service: "S3",
    fullName: "Simple Storage Service",
    description: "Object storage service. One of the most commonly misconfigured AWS services, leading to massive data breaches.",
    misconfigurations: [
      { id: "S3-001", title: "Public bucket via ACL", severity: "critical", description: "Bucket or object ACLs granting access to AllUsers or AuthenticatedUsers expose data to the internet or any AWS account.", detection: "aws s3api get-bucket-acl --bucket BUCKET", remediation: "Remove public ACLs. Enable S3 Block Public Access at the account level." },
      { id: "S3-002", title: "Public bucket via bucket policy", severity: "critical", description: "Bucket policies with Principal: '*' and no restrictive conditions allow anyone to read, list, or write to the bucket.", detection: "aws s3api get-bucket-policy --bucket BUCKET", remediation: "Remove wildcards. Use aws:SourceVpc, aws:SourceIp, or aws:PrincipalOrgID conditions." },
      { id: "S3-003", title: "S3 Block Public Access disabled", severity: "high", description: "Account-level or bucket-level Block Public Access settings are disabled, allowing public ACLs and policies to take effect.", detection: "aws s3control get-public-access-block --account-id ACCOUNT_ID", remediation: "Enable all four Block Public Access settings at the account level." },
      { id: "S3-004", title: "Server-side encryption not enabled", severity: "medium", description: "Objects stored without encryption at rest can be read by anyone with physical access to the storage media or via backup leaks.", detection: "aws s3api get-bucket-encryption --bucket BUCKET", remediation: "Enable default encryption with SSE-S3 (AES-256) or SSE-KMS. Use bucket policy to deny unencrypted uploads." },
      { id: "S3-005", title: "Versioning not enabled", severity: "medium", description: "Without versioning, accidental deletions or overwrites cannot be recovered. Ransomware can permanently destroy data.", detection: "aws s3api get-bucket-versioning --bucket BUCKET", remediation: "Enable versioning and configure lifecycle rules to manage version costs." },
      { id: "S3-006", title: "No access logging", severity: "medium", description: "Without server access logging or CloudTrail data events, access to sensitive buckets cannot be audited.", detection: "aws s3api get-bucket-logging --bucket BUCKET", remediation: "Enable S3 server access logging or CloudTrail S3 data events for sensitive buckets." },
      { id: "S3-007", title: "HTTPS not enforced", severity: "medium", description: "Bucket policy does not deny HTTP (non-TLS) requests, allowing data in transit to be intercepted.", detection: "Check bucket policy for aws:SecureTransport condition", remediation: "Add bucket policy statement: Effect: Deny, Condition: { Bool: { 'aws:SecureTransport': false } }." },
      { id: "S3-008", title: "Cross-account access without ExternalId", severity: "high", description: "Bucket policies granting cross-account access without conditions can be exploited if the trusted account is compromised.", detection: "Review bucket policies for cross-account Principal entries", remediation: "Use aws:PrincipalOrgID to restrict to your organization, or require specific IAM roles." },
      { id: "S3-009", title: "Object Lock not used for compliance data", severity: "medium", description: "Regulatory data (financial records, healthcare, legal holds) stored without Object Lock can be tampered with or deleted.", detection: "aws s3api get-object-lock-configuration --bucket BUCKET", remediation: "Enable Object Lock in Governance or Compliance mode for regulatory data." },
      { id: "S3-010", title: "Bucket allows arbitrary uploads", severity: "high", description: "A bucket policy allowing s3:PutObject from any principal can be used to store malicious content or incur costs.", detection: "Review bucket policy for permissive PutObject statements", remediation: "Restrict PutObject to specific IAM principals and add content-type/size conditions." }
    ],
    attacks: [
      { name: "S3 bucket enumeration", description: "Brute-force or guess S3 bucket names using common patterns (company-backup, company-dev, company-logs) to find misconfigured public buckets.", mitre: "T1530", steps: ["Generate bucket name wordlist", "Use aws s3 ls s3://BUCKET --no-sign-request", "Or HEAD request: curl -I https://BUCKET.s3.amazonaws.com/", "403 = exists but private, 404 = doesn't exist, 200 = public"] },
      { name: "Data exfiltration via presigned URLs", description: "An attacker with s3:GetObject permission can generate presigned URLs that grant temporary access without credentials, bypassing network controls.", mitre: "T1567", steps: ["Generate presigned URL: aws s3 presign s3://bucket/secret.txt --expires-in 3600", "Share URL externally — no AWS credentials needed to download"] },
      { name: "Bucket takeover via deleted bucket", description: "If a bucket referenced in DNS (CNAME) or application code is deleted, an attacker can recreate it in their own account.", mitre: "T1584", steps: ["Find dangling S3 references (CNAME, CDN origin, application config)", "Verify bucket doesn't exist (404)", "Create bucket with same name in attacker's account", "Serve malicious content"] }
    ],
    hardening: [
      "Enable S3 Block Public Access at the account level",
      "Enable default encryption (SSE-S3 or SSE-KMS) on all buckets",
      "Enable versioning and MFA Delete for critical buckets",
      "Use VPC endpoints for S3 access from within VPCs",
      "Enable S3 access logging or CloudTrail data events",
      "Enforce HTTPS-only via bucket policy",
      "Use S3 Object Lock for compliance data",
      "Implement lifecycle rules to transition/expire old data",
      "Use Macie to discover and classify sensitive data in S3",
      "Review S3 Access Analyzer findings regularly"
    ],
    auditCommands: [
      "aws s3api list-buckets --query 'Buckets[*].Name'",
      "aws s3api get-bucket-acl --bucket BUCKET",
      "aws s3api get-bucket-policy --bucket BUCKET",
      "aws s3api get-bucket-encryption --bucket BUCKET",
      "aws s3api get-bucket-versioning --bucket BUCKET",
      "aws s3api get-bucket-logging --bucket BUCKET",
      "aws s3api get-public-access-block --bucket BUCKET",
      "aws s3api get-bucket-policy-status --bucket BUCKET"
    ]
  },
  {
    service: "EC2",
    fullName: "Elastic Compute Cloud",
    description: "Virtual servers in the cloud. Security concerns include network exposure, metadata service attacks, and unpatched instances.",
    misconfigurations: [
      { id: "EC2-001", title: "Security group allows 0.0.0.0/0 on SSH/RDP", severity: "critical", description: "Inbound rules allowing SSH (22) or RDP (3389) from any IP expose instances to brute-force and exploitation from the internet.", detection: "aws ec2 describe-security-groups --query 'SecurityGroups[*].{ID:GroupId,Rules:IpPermissions[?contains(IpRanges[].CidrIp,`0.0.0.0/0`)]}'", remediation: "Restrict SSH/RDP to specific CIDR ranges or use SSM Session Manager instead." },
      { id: "EC2-002", title: "IMDSv1 enabled (metadata service)", severity: "high", description: "Instance Metadata Service v1 uses a simple HTTP GET without session tokens, making it vulnerable to SSRF-based credential theft.", detection: "aws ec2 describe-instances --query 'Reservations[*].Instances[*].{ID:InstanceId,IMDS:MetadataOptions.HttpTokens}'", remediation: "Enforce IMDSv2 (HttpTokens: required) on all instances. Set HttpPutResponseHopLimit to 1." },
      { id: "EC2-003", title: "EBS volumes not encrypted", severity: "medium", description: "Unencrypted EBS volumes can be accessed via snapshots or physical media if the underlying hardware is compromised.", detection: "aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].{ID:VolumeId,Size:Size}'", remediation: "Enable default EBS encryption at the account level. Encrypt existing volumes by creating encrypted snapshots." },
      { id: "EC2-004", title: "Public IP assigned to instances in private subnets", severity: "high", description: "Instances meant to be internal-only have public IPs, exposing them directly to the internet.", detection: "aws ec2 describe-instances --query 'Reservations[*].Instances[?PublicIpAddress!=null].{ID:InstanceId,PublicIP:PublicIpAddress,SubnetId:SubnetId}'", remediation: "Disable auto-assign public IP for private subnets. Use NAT Gateway for outbound internet access." },
      { id: "EC2-005", title: "Unused security groups with permissive rules", severity: "medium", description: "Security groups not attached to any resource but with wide-open rules can be attached later, accidentally exposing resources.", detection: "aws ec2 describe-security-groups --query 'SecurityGroups[*].GroupId' vs. describe-network-interfaces", remediation: "Delete unused security groups. Audit and tighten rules on remaining groups." },
      { id: "EC2-006", title: "User data scripts contain secrets", severity: "critical", description: "EC2 user data (startup scripts) may contain plaintext passwords, API keys, or tokens. User data is accessible from the metadata service.", detection: "aws ec2 describe-instance-attribute --instance-id i-xxx --attribute userData --query UserData.Value --output text | base64 -d", remediation: "Store secrets in Secrets Manager or Parameter Store. Retrieve them at runtime, not in user data." },
      { id: "EC2-007", title: "Outdated AMIs with known vulnerabilities", severity: "high", description: "Instances launched from old AMIs may have unpatched operating systems and software with known CVEs.", detection: "aws ec2 describe-images --owners self --query 'sort_by(Images, &CreationDate)[*].{ID:ImageId,Date:CreationDate,Name:Name}'", remediation: "Use AWS Inspector to scan instances. Build fresh AMIs monthly with latest patches." },
      { id: "EC2-008", title: "No termination protection on critical instances", severity: "medium", description: "Critical production instances without termination protection can be accidentally terminated, causing outages.", detection: "aws ec2 describe-instance-attribute --instance-id i-xxx --attribute disableApiTermination", remediation: "Enable termination protection and stop protection on production instances." },
      { id: "EC2-009", title: "Default VPC in use", severity: "medium", description: "The default VPC has permissive default settings (public subnets, internet gateway, permissive NACL) that may not meet security requirements.", detection: "aws ec2 describe-vpcs --query 'Vpcs[?IsDefault==`true`]'", remediation: "Create custom VPCs with proper subnet isolation. Remove unused default VPCs." },
      { id: "EC2-010", title: "Snapshot shared publicly", severity: "critical", description: "EBS snapshots shared with 'all' (public) expose the volume data to any AWS account, potentially leaking sensitive data.", detection: "aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[*].SnapshotId' | xargs -I{} aws ec2 describe-snapshot-attribute --snapshot-id {} --attribute createVolumePermission", remediation: "Remove public sharing. Use aws ec2 modify-snapshot-attribute to restrict to specific accounts." }
    ],
    attacks: [
      { name: "SSRF to IMDS credential theft", description: "Exploit SSRF in a web application running on EC2 to query the instance metadata service and steal IAM role temporary credentials.", mitre: "T1552.005", steps: ["Find SSRF: curl 'http://app.example.com/proxy?url=http://169.254.169.254/latest/meta-data/'", "Get role: /latest/meta-data/iam/security-credentials/", "Get credentials: /latest/meta-data/iam/security-credentials/ROLE_NAME", "Use AccessKeyId, SecretAccessKey, Token externally"] },
      { name: "Snapshot exfiltration", description: "An attacker with ec2:CreateSnapshot and ec2:ModifySnapshotAttribute can snapshot a volume and share it with their own account.", mitre: "T1537", steps: ["Create snapshot of target volume", "Modify snapshot to share with attacker's account", "In attacker's account: create volume from snapshot", "Mount and read all data"] },
      { name: "Security group manipulation", description: "An attacker with ec2:AuthorizeSecurityGroupIngress can open ports to allow their IP to connect to internal instances.", mitre: "T1562.007", steps: ["Find security group attached to target instance", "Add inbound rule allowing attacker's IP on port 22 or target service port", "Connect to instance", "Remove the rule after to cover tracks"] }
    ],
    hardening: [
      "Enforce IMDSv2 (require tokens) on all instances",
      "Use SSM Session Manager instead of SSH for instance access",
      "Enable EBS default encryption at the account level",
      "Disable auto-assign public IP for private subnets",
      "Use VPC flow logs for network traffic monitoring",
      "Apply security groups with least-privilege rules",
      "Use AWS Inspector for vulnerability scanning",
      "Build golden AMIs with CIS benchmarks and update monthly",
      "Enable termination protection on production instances",
      "Never put secrets in user data scripts"
    ],
    auditCommands: [
      "aws ec2 describe-instances --query 'Reservations[*].Instances[*].{ID:InstanceId,Type:InstanceType,State:State.Name,PublicIP:PublicIpAddress,IAMRole:IamInstanceProfile.Arn,IMDS:MetadataOptions.HttpTokens}'",
      "aws ec2 describe-security-groups --query 'SecurityGroups[*].{ID:GroupId,Name:GroupName,Ingress:IpPermissions}'",
      "aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`]'",
      "aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[*].{ID:SnapshotId,Encrypted:Encrypted}'"
    ]
  },
  {
    service: "Lambda",
    fullName: "AWS Lambda",
    description: "Serverless compute service. Security risks include overprivileged execution roles, code injection, and event data injection.",
    misconfigurations: [
      { id: "LAMBDA-001", title: "Overprivileged execution role", severity: "high", description: "Lambda function's IAM role has admin or broad permissions (Action: *, Resource: *), violating least privilege.", detection: "aws lambda list-functions --query 'Functions[*].{Name:FunctionName,Role:Role}' then check each role's policies", remediation: "Scope the execution role to only the services and actions the function actually uses." },
      { id: "LAMBDA-002", title: "Environment variables contain secrets in plaintext", severity: "critical", description: "API keys, database passwords, and tokens stored as plaintext environment variables are visible to anyone with lambda:GetFunction permission.", detection: "aws lambda get-function-configuration --function-name FUNC --query 'Environment.Variables'", remediation: "Use KMS-encrypted environment variables or retrieve secrets from Secrets Manager at runtime." },
      { id: "LAMBDA-003", title: "Function URL with no auth", severity: "high", description: "Lambda function URLs configured with AuthType: NONE are publicly accessible without any authentication.", detection: "aws lambda list-function-url-configs --function-name FUNC", remediation: "Set AuthType to AWS_IAM or add custom authorization logic." },
      { id: "LAMBDA-004", title: "No resource-based policy restrictions", severity: "medium", description: "Lambda resource policy allows invocation from any account or service without conditions.", detection: "aws lambda get-policy --function-name FUNC", remediation: "Restrict invocation sources using aws:SourceAccount and aws:SourceArn conditions." },
      { id: "LAMBDA-005", title: "Outdated runtime version", severity: "medium", description: "Lambda functions running deprecated runtimes (Python 3.7, Node.js 14, etc.) no longer receive security patches.", detection: "aws lambda list-functions --query 'Functions[*].{Name:FunctionName,Runtime:Runtime}'", remediation: "Update to the latest supported runtime version. Use Lambda layers for shared dependencies." },
      { id: "LAMBDA-006", title: "No VPC configuration for database access", severity: "medium", description: "Functions accessing RDS or internal resources without VPC configuration route traffic over the public internet.", detection: "aws lambda get-function-configuration --function-name FUNC --query 'VpcConfig'", remediation: "Configure the function to run in a VPC with private subnets and appropriate security groups." },
      { id: "LAMBDA-007", title: "Concurrency not limited", severity: "low", description: "Without reserved concurrency, a single function can consume all account-level concurrency, causing other functions to throttle.", detection: "aws lambda get-function-concurrency --function-name FUNC", remediation: "Set reserved concurrency for critical functions. Use provisioned concurrency for latency-sensitive functions." },
      { id: "LAMBDA-008", title: "No dead letter queue configured", severity: "low", description: "Failed asynchronous invocations are silently dropped without a DLQ, losing error data needed for debugging and security analysis.", detection: "aws lambda get-function-configuration --function-name FUNC --query 'DeadLetterConfig'", remediation: "Configure a DLQ (SQS queue or SNS topic) for asynchronous invocation failures." },
      { id: "LAMBDA-009", title: "Code signing not enforced", severity: "medium", description: "Without code signing, any code package can be deployed to the function, enabling supply chain attacks or unauthorized modifications.", detection: "aws lambda get-function-code-signing-config --function-name FUNC", remediation: "Create a code signing configuration with trusted signing profiles and enforce it on the function." },
      { id: "LAMBDA-010", title: "Layers from untrusted sources", severity: "high", description: "Lambda layers from public or third-party sources may contain malicious code that runs in the function's context with its IAM permissions.", detection: "aws lambda get-function-configuration --function-name FUNC --query 'Layers'", remediation: "Audit all layer contents. Prefer layers built in-house or from verified publishers." }
    ],
    attacks: [
      { name: "Event injection", description: "Attacker manipulates the event data (API Gateway request, S3 event, SQS message) to inject malicious payloads into the Lambda function.", mitre: "T1190", steps: ["Identify event source (API Gateway, S3, SQS, etc.)", "Craft malicious payload in the event format", "Trigger function with payload", "Exploit command injection, SQL injection, or deserialization in handler"] },
      { name: "Privilege escalation via Lambda execution", description: "Attacker with lambda:CreateFunction and iam:PassRole creates a function with an admin role and invokes it.", mitre: "T1078.004", steps: ["Create function with admin execution role", "Handler code: create new IAM user with admin", "Invoke function", "Use new credentials"] },
      { name: "Credential harvesting from environment", description: "Lambda runtime environment variables and /tmp storage may contain sensitive data from previous invocations (warm starts).", mitre: "T1552.001", steps: ["Deploy malicious layer or modify function code", "Read environment variables and AWS_SESSION_TOKEN", "Scan /tmp for leftover files from previous invocations", "Exfiltrate credentials"] }
    ],
    hardening: [
      "Apply least-privilege IAM policies to execution roles",
      "Encrypt environment variables with KMS customer-managed keys",
      "Use Lambda function URLs with AWS_IAM auth, not NONE",
      "Configure functions in VPC for internal resource access",
      "Set reserved concurrency limits",
      "Enable code signing with trusted profiles",
      "Validate and sanitize all event input data",
      "Use Powertools for structured logging and tracing",
      "Configure dead letter queues for async invocations",
      "Keep runtimes updated to latest supported versions"
    ],
    auditCommands: [
      "aws lambda list-functions --query 'Functions[*].{Name:FunctionName,Runtime:Runtime,Role:Role,Timeout:Timeout,MemorySize:MemorySize}'",
      "aws lambda get-function-configuration --function-name FUNC",
      "aws lambda get-policy --function-name FUNC",
      "aws lambda list-function-url-configs --function-name FUNC"
    ]
  },
  {
    service: "VPC",
    fullName: "Virtual Private Cloud",
    description: "Network isolation layer for AWS resources. Misconfigurations can expose internal services to the internet.",
    misconfigurations: [
      { id: "VPC-001", title: "No VPC flow logs enabled", severity: "high", description: "Without flow logs, network traffic to and from VPC resources cannot be monitored for anomalies, data exfiltration, or unauthorized access.", detection: "aws ec2 describe-flow-logs --filter 'Name=resource-id,Values=vpc-xxx'", remediation: "Enable VPC flow logs to CloudWatch Logs or S3 for all VPCs." },
      { id: "VPC-002", title: "Default NACL allows all traffic", severity: "medium", description: "The default Network ACL allows all inbound and outbound traffic. Custom NACLs should be used for defense in depth.", detection: "aws ec2 describe-network-acls --query 'NetworkAcls[?IsDefault==`true`].{ID:NetworkAclId,Entries:Entries}'", remediation: "Create custom NACLs with explicit allow/deny rules. Remove allow-all rules." },
      { id: "VPC-003", title: "VPC peering without route restrictions", severity: "high", description: "VPC peering connections with overly broad routing can expose internal resources across peered VPCs.", detection: "aws ec2 describe-vpc-peering-connections && aws ec2 describe-route-tables", remediation: "Restrict routes to only necessary CIDR ranges. Use security groups to further limit cross-VPC access." },
      { id: "VPC-004", title: "No VPC endpoints for AWS services", severity: "medium", description: "Traffic to AWS services like S3 and DynamoDB routes through the internet gateway instead of staying within AWS's private network.", detection: "aws ec2 describe-vpc-endpoints --filters 'Name=vpc-id,Values=vpc-xxx'", remediation: "Create VPC gateway endpoints for S3 and DynamoDB. Use interface endpoints for other services." },
      { id: "VPC-005", title: "Public subnets with database instances", severity: "critical", description: "Database instances (RDS, ElastiCache, Redshift) placed in public subnets with internet gateway routes are directly exposed.", detection: "Cross-reference subnet route tables (internet gateway) with RDS/ElastiCache subnet groups", remediation: "Move databases to private subnets. Use NAT Gateway for outbound-only internet access if needed." },
      { id: "VPC-006", title: "DNS resolution not enabled for VPC", severity: "low", description: "Without DNS resolution, instances cannot resolve AWS service endpoints or private hosted zone records.", detection: "aws ec2 describe-vpc-attribute --vpc-id vpc-xxx --attribute enableDnsSupport", remediation: "Enable DNS support and DNS hostnames for the VPC." },
      { id: "VPC-007", title: "Transit Gateway without route domain isolation", severity: "high", description: "All VPCs attached to a Transit Gateway can communicate with each other by default, breaking network segmentation.", detection: "aws ec2 describe-transit-gateway-route-tables", remediation: "Use separate route tables and associations to isolate VPC communication domains." },
      { id: "VPC-008", title: "NAT Gateway in availability zone without redundancy", severity: "medium", description: "A single NAT Gateway creates a single point of failure for outbound internet access from private subnets.", detection: "aws ec2 describe-nat-gateways --query 'NatGateways[*].{SubnetId:SubnetId,AZ:Tags}'", remediation: "Deploy NAT Gateways in each availability zone used by private subnets." }
    ],
    hardening: [
      "Enable VPC flow logs for all VPCs (accept + reject)",
      "Use private subnets for databases and application servers",
      "Create VPC endpoints for frequently used AWS services",
      "Implement NACLs as an additional layer of defense",
      "Use Transit Gateway route tables for network segmentation",
      "Deploy NAT Gateways in multiple AZs for redundancy",
      "Use Security Hub for automated VPC configuration checks",
      "Implement AWS Network Firewall for advanced traffic inspection"
    ],
    auditCommands: [
      "aws ec2 describe-vpcs --query 'Vpcs[*].{ID:VpcId,CIDR:CidrBlock,Default:IsDefault}'",
      "aws ec2 describe-subnets --query 'Subnets[*].{ID:SubnetId,VPC:VpcId,AZ:AvailabilityZone,Public:MapPublicIpOnLaunch}'",
      "aws ec2 describe-flow-logs",
      "aws ec2 describe-vpc-endpoints",
      "aws ec2 describe-nat-gateways"
    ]
  },
  {
    service: "CloudTrail",
    fullName: "AWS CloudTrail",
    description: "API activity logging service. Essential for security monitoring, incident response, and compliance. Disabling it is a red flag.",
    misconfigurations: [
      { id: "CT-001", title: "CloudTrail not enabled in all regions", severity: "critical", description: "An attacker can operate in a region without CloudTrail logging to avoid detection.", detection: "aws cloudtrail describe-trails --query 'trailList[*].{Name:Name,IsMultiRegion:IsMultiRegionTrail,IsOrg:IsOrganizationTrail}'", remediation: "Create a multi-region trail or use AWS Organizations trail." },
      { id: "CT-002", title: "CloudTrail log file validation disabled", severity: "high", description: "Without log file integrity validation, an attacker can modify or delete logs without detection.", detection: "aws cloudtrail describe-trails --query 'trailList[*].{Name:Name,Validation:LogFileValidationEnabled}'", remediation: "Enable log file validation: aws cloudtrail update-trail --name TRAIL --enable-log-file-validation." },
      { id: "CT-003", title: "CloudTrail logs not encrypted", severity: "medium", description: "Logs stored in S3 without KMS encryption can be read by anyone with S3 access to the bucket.", detection: "aws cloudtrail describe-trails --query 'trailList[*].{Name:Name,KMSKeyId:KmsKeyId}'", remediation: "Enable SSE-KMS encryption on the CloudTrail S3 bucket with a customer-managed key." },
      { id: "CT-004", title: "CloudTrail S3 bucket publicly accessible", severity: "critical", description: "The S3 bucket receiving CloudTrail logs is publicly accessible, exposing all API activity to the internet.", detection: "aws s3api get-bucket-acl --bucket CLOUDTRAIL_BUCKET && aws s3api get-public-access-block --bucket CLOUDTRAIL_BUCKET", remediation: "Enable Block Public Access on the CloudTrail S3 bucket. Review bucket policy." },
      { id: "CT-005", title: "No CloudWatch integration for real-time alerts", severity: "high", description: "Without CloudWatch Logs integration, CloudTrail events cannot trigger real-time alerts for suspicious activity.", detection: "aws cloudtrail describe-trails --query 'trailList[*].{Name:Name,CWLogGroup:CloudWatchLogsLogGroupArn}'", remediation: "Configure CloudTrail to send logs to CloudWatch Logs. Create metric filters and alarms for critical events." },
      { id: "CT-006", title: "Data events not logged", severity: "medium", description: "Management events are logged but data events (S3 object access, Lambda invocations) are not, missing potential data access abuse.", detection: "aws cloudtrail get-event-selectors --trail-name TRAIL", remediation: "Enable data event logging for S3 buckets and Lambda functions containing sensitive data." }
    ],
    hardening: [
      "Enable multi-region trail with log file validation",
      "Encrypt logs with KMS customer-managed key",
      "Enable CloudWatch Logs integration for real-time alerting",
      "Protect the CloudTrail S3 bucket with Block Public Access and MFA Delete",
      "Set up metric filters for: root login, IAM changes, security group changes, NACL changes, CloudTrail changes, console login failures",
      "Enable data events for sensitive S3 buckets and Lambda functions",
      "Use AWS Organizations trail for centralized logging",
      "Implement S3 lifecycle rules to archive old logs to Glacier"
    ],
    auditCommands: [
      "aws cloudtrail describe-trails",
      "aws cloudtrail get-trail-status --name TRAIL",
      "aws cloudtrail get-event-selectors --trail-name TRAIL",
      "aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin --start-time 2024-01-01"
    ]
  },
  {
    service: "KMS",
    fullName: "Key Management Service",
    description: "Managed encryption key service. Controls who can encrypt, decrypt, and manage cryptographic keys across all AWS services.",
    misconfigurations: [
      { id: "KMS-001", title: "Key policy allows public access", severity: "critical", description: "Key policy with Principal: '*' allows any AWS account to use the key for encryption or decryption.", detection: "aws kms list-keys | xargs -I{} aws kms get-key-policy --key-id {} --policy-name default", remediation: "Restrict key policies to specific IAM principals and accounts." },
      { id: "KMS-002", title: "Key rotation not enabled", severity: "medium", description: "Customer-managed keys without automatic rotation may be compromised without detection over time.", detection: "aws kms get-key-rotation-status --key-id KEY_ID", remediation: "Enable automatic key rotation: aws kms enable-key-rotation --key-id KEY_ID." },
      { id: "KMS-003", title: "AWS-managed keys used for sensitive data", severity: "medium", description: "AWS-managed keys (aws/s3, aws/ebs) cannot have custom policies, rotation schedules, or cross-account access controls.", detection: "Check if resources use aws/* key aliases instead of custom CMKs", remediation: "Create customer-managed keys with appropriate key policies for sensitive data." },
      { id: "KMS-004", title: "Grants not reviewed", severity: "medium", description: "KMS grants provide temporary access to keys and may accumulate over time, creating unauthorized access paths.", detection: "aws kms list-grants --key-id KEY_ID", remediation: "Review and revoke unnecessary grants regularly. Use IAM policies instead of grants where possible." }
    ],
    hardening: [
      "Use customer-managed keys for sensitive data",
      "Enable automatic key rotation",
      "Restrict key policies to specific principals",
      "Use separate keys for different data classification levels",
      "Monitor key usage via CloudTrail",
      "Enable key deletion protection (waiting period)",
      "Review grants periodically and revoke unnecessary ones"
    ],
    auditCommands: [
      "aws kms list-keys --query 'Keys[*].KeyId'",
      "aws kms describe-key --key-id KEY_ID",
      "aws kms get-key-policy --key-id KEY_ID --policy-name default",
      "aws kms get-key-rotation-status --key-id KEY_ID",
      "aws kms list-grants --key-id KEY_ID"
    ]
  },
  {
    service: "GuardDuty",
    fullName: "Amazon GuardDuty",
    description: "Threat detection service that continuously monitors for malicious activity and unauthorized behavior across AWS accounts.",
    misconfigurations: [
      { id: "GD-001", title: "GuardDuty not enabled", severity: "critical", description: "Without GuardDuty, AWS has no automated threat detection for reconnaissance, instance compromise, or account compromise.", detection: "aws guardduty list-detectors", remediation: "Enable GuardDuty in all regions: aws guardduty create-detector --enable." },
      { id: "GD-002", title: "S3 protection not enabled", severity: "high", description: "GuardDuty S3 protection monitors S3 data events for suspicious access patterns. Without it, S3-based threats are undetected.", detection: "aws guardduty get-detector --detector-id ID --query 'DataSources.S3Logs'", remediation: "Enable S3 protection in GuardDuty settings." },
      { id: "GD-003", title: "Findings not exported", severity: "medium", description: "GuardDuty findings not exported to S3 or EventBridge are only available for 90 days and cannot be analyzed long-term.", detection: "aws guardduty list-publishing-destinations --detector-id ID", remediation: "Configure finding export to S3 and EventBridge for alerting." },
      { id: "GD-004", title: "High-severity findings not actioned", severity: "high", description: "Unresolved high-severity findings indicate active threats that are not being investigated or remediated.", detection: "aws guardduty list-findings --detector-id ID --finding-criteria '{\"Criterion\":{\"severity\":{\"Gte\":7}}}'", remediation: "Create an incident response workflow triggered by high-severity findings via EventBridge." }
    ],
    hardening: [
      "Enable GuardDuty in all regions with a delegated administrator",
      "Enable all protection plans: S3, EKS, RDS, Lambda, Malware",
      "Export findings to S3 for long-term retention",
      "Create EventBridge rules for high/critical findings",
      "Integrate with Security Hub for centralized finding management",
      "Suppress known false positives with suppression rules",
      "Review findings weekly and track remediation"
    ],
    auditCommands: [
      "aws guardduty list-detectors",
      "aws guardduty get-detector --detector-id ID",
      "aws guardduty get-findings-statistics --detector-id ID --finding-statistic-types COUNT_BY_SEVERITY",
      "aws guardduty list-findings --detector-id ID --sort-criteria '{\"AttributeName\":\"severity\",\"OrderBy\":\"DESC\"}'"
    ]
  },
  {
    service: "RDS",
    fullName: "Relational Database Service",
    description: "Managed relational databases. Common misconfigurations include public access, weak authentication, and unencrypted storage.",
    misconfigurations: [
      { id: "RDS-001", title: "Database publicly accessible", severity: "critical", description: "RDS instance with PubliclyAccessible=true and permissive security group rules exposes the database to the internet.", detection: "aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible==`true`].{ID:DBInstanceIdentifier,Engine:Engine}'", remediation: "Set PubliclyAccessible to false. Place in private subnets." },
      { id: "RDS-002", title: "Storage encryption disabled", severity: "high", description: "Database storage not encrypted at rest leaves data vulnerable to physical media theft or snapshot exposure.", detection: "aws rds describe-db-instances --query 'DBInstances[?StorageEncrypted==`false`].{ID:DBInstanceIdentifier}'", remediation: "Enable encryption. For existing instances: create encrypted snapshot, restore from it." },
      { id: "RDS-003", title: "Automated backups disabled", severity: "high", description: "Without automated backups, data cannot be recovered after ransomware, accidental deletion, or corruption.", detection: "aws rds describe-db-instances --query 'DBInstances[?BackupRetentionPeriod==`0`]'", remediation: "Set backup retention period to at least 7 days." },
      { id: "RDS-004", title: "Default master username", severity: "medium", description: "Using 'admin', 'root', or 'postgres' as the master username makes brute-force attacks easier.", detection: "aws rds describe-db-instances --query 'DBInstances[*].{ID:DBInstanceIdentifier,User:MasterUsername}'", remediation: "Use a non-default master username. Rotate credentials regularly." },
      { id: "RDS-005", title: "Multi-AZ not enabled for production", severity: "medium", description: "Single-AZ deployments have no automatic failover, resulting in downtime during AZ failures or maintenance.", detection: "aws rds describe-db-instances --query 'DBInstances[?MultiAZ==`false`].{ID:DBInstanceIdentifier}'", remediation: "Enable Multi-AZ for all production databases." },
      { id: "RDS-006", title: "Enhanced monitoring disabled", severity: "low", description: "Without enhanced monitoring, OS-level metrics (CPU, memory, I/O) are unavailable for performance and security analysis.", detection: "aws rds describe-db-instances --query 'DBInstances[*].{ID:DBInstanceIdentifier,Monitoring:MonitoringInterval}'", remediation: "Enable enhanced monitoring with at least 60-second granularity." },
      { id: "RDS-007", title: "IAM authentication not enabled", severity: "medium", description: "Password-only authentication is weaker than IAM database authentication, which uses short-lived tokens.", detection: "aws rds describe-db-instances --query 'DBInstances[*].{ID:DBInstanceIdentifier,IAMAuth:IAMDatabaseAuthenticationEnabled}'", remediation: "Enable IAM database authentication for supported engines (MySQL, PostgreSQL)." },
      { id: "RDS-008", title: "Deletion protection not enabled", severity: "medium", description: "Production databases without deletion protection can be accidentally or maliciously deleted.", detection: "aws rds describe-db-instances --query 'DBInstances[*].{ID:DBInstanceIdentifier,DeletionProtection:DeletionProtection}'", remediation: "Enable deletion protection on all production databases." }
    ],
    hardening: [
      "Place RDS in private subnets with PubliclyAccessible=false",
      "Enable storage encryption with customer-managed KMS key",
      "Enable automated backups with 7+ day retention",
      "Enable Multi-AZ for production workloads",
      "Use IAM database authentication where supported",
      "Enable enhanced monitoring and Performance Insights",
      "Enable deletion protection on production databases",
      "Use RDS Proxy for connection pooling and IAM auth",
      "Regularly rotate master credentials via Secrets Manager"
    ],
    auditCommands: [
      "aws rds describe-db-instances --query 'DBInstances[*].{ID:DBInstanceIdentifier,Engine:Engine,Public:PubliclyAccessible,Encrypted:StorageEncrypted,MultiAZ:MultiAZ,BackupDays:BackupRetentionPeriod}'",
      "aws rds describe-db-snapshots --query 'DBSnapshots[*].{ID:DBSnapshotIdentifier,Encrypted:Encrypted}'"
    ]
  },
  {
    service: "SecretsManager",
    fullName: "AWS Secrets Manager",
    description: "Service for storing, rotating, and managing secrets (API keys, database credentials, tokens). Critical for eliminating hardcoded secrets.",
    misconfigurations: [
      { id: "SM-001", title: "Automatic rotation not configured", severity: "high", description: "Secrets without automatic rotation may remain valid indefinitely after compromise.", detection: "aws secretsmanager list-secrets --query 'SecretList[?RotationEnabled==`false`].{Name:Name}'", remediation: "Configure rotation Lambda functions for each secret type." },
      { id: "SM-002", title: "Resource policy too permissive", severity: "high", description: "Secret resource policies with Principal: '*' allow any authenticated AWS user to retrieve the secret.", detection: "aws secretsmanager get-resource-policy --secret-id SECRET_NAME", remediation: "Restrict to specific IAM principals and add conditions." },
      { id: "SM-003", title: "Secrets not encrypted with CMK", severity: "medium", description: "Secrets encrypted with the default AWS-managed key cannot have custom key policies or cross-account access controls.", detection: "aws secretsmanager describe-secret --secret-id SECRET --query 'KmsKeyId'", remediation: "Use a customer-managed KMS key for sensitive secrets." },
      { id: "SM-004", title: "Old secret versions not cleaned up", severity: "low", description: "Accumulation of old secret versions increases storage costs and may retain compromised values.", detection: "aws secretsmanager list-secret-version-ids --secret-id SECRET", remediation: "Old versions are automatically deleted after rotation, but review if custom rotation is used." }
    ],
    hardening: [
      "Enable automatic rotation for all secrets",
      "Use customer-managed KMS keys for encryption",
      "Apply least-privilege resource policies",
      "Monitor secret access via CloudTrail",
      "Use Secrets Manager instead of Parameter Store for sensitive credentials",
      "Tag secrets for cost allocation and access control"
    ],
    auditCommands: [
      "aws secretsmanager list-secrets --query 'SecretList[*].{Name:Name,Rotation:RotationEnabled,LastRotated:LastRotatedDate}'",
      "aws secretsmanager describe-secret --secret-id SECRET",
      "aws secretsmanager get-resource-policy --secret-id SECRET"
    ]
  }
];

export const AWS_PRIVILEGE_ESCALATION = [
  { id: "PE-001", method: "CreatePolicyVersion", description: "Create a new version of an IAM policy with admin permissions and set it as default.", required_permissions: ["iam:CreatePolicyVersion"], severity: "critical" },
  { id: "PE-002", method: "SetDefaultPolicyVersion", description: "Set an older, more permissive policy version as the default.", required_permissions: ["iam:SetDefaultPolicyVersion"], severity: "critical" },
  { id: "PE-003", method: "CreateAccessKey", description: "Create access keys for a more privileged user.", required_permissions: ["iam:CreateAccessKey"], severity: "high" },
  { id: "PE-004", method: "CreateLoginProfile", description: "Create a console login for a more privileged user who only has API access.", required_permissions: ["iam:CreateLoginProfile"], severity: "high" },
  { id: "PE-005", method: "UpdateLoginProfile", description: "Change the password of a more privileged user.", required_permissions: ["iam:UpdateLoginProfile"], severity: "high" },
  { id: "PE-006", method: "AttachUserPolicy", description: "Attach AdministratorAccess or other high-privilege managed policies to the current user.", required_permissions: ["iam:AttachUserPolicy"], severity: "critical" },
  { id: "PE-007", method: "AttachGroupPolicy", description: "Attach a high-privilege managed policy to a group the current user belongs to.", required_permissions: ["iam:AttachGroupPolicy"], severity: "critical" },
  { id: "PE-008", method: "AttachRolePolicy", description: "Attach a high-privilege managed policy to a role the current user can assume.", required_permissions: ["iam:AttachRolePolicy"], severity: "critical" },
  { id: "PE-009", method: "PutUserPolicy", description: "Add an inline policy to the current user with escalated permissions.", required_permissions: ["iam:PutUserPolicy"], severity: "critical" },
  { id: "PE-010", method: "PutGroupPolicy", description: "Add an inline policy to a group the current user belongs to.", required_permissions: ["iam:PutGroupPolicy"], severity: "critical" },
  { id: "PE-011", method: "PutRolePolicy", description: "Add an inline policy to a role the current user can assume.", required_permissions: ["iam:PutRolePolicy"], severity: "critical" },
  { id: "PE-012", method: "AddUserToGroup", description: "Add the current user to a group with higher privileges.", required_permissions: ["iam:AddUserToGroup"], severity: "high" },
  { id: "PE-013", method: "UpdateAssumeRolePolicy", description: "Modify an admin role's trust policy to allow the current user to assume it.", required_permissions: ["iam:UpdateAssumeRolePolicy"], severity: "critical" },
  { id: "PE-014", method: "PassRole + Lambda", description: "Pass an admin role to a new Lambda function, then invoke it to perform privileged actions.", required_permissions: ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], severity: "critical" },
  { id: "PE-015", method: "PassRole + EC2", description: "Launch an EC2 instance with an admin instance profile, then SSH in and use the role.", required_permissions: ["iam:PassRole", "ec2:RunInstances"], severity: "critical" },
  { id: "PE-016", method: "PassRole + CloudFormation", description: "Create a CloudFormation stack with an admin role that creates privileged resources.", required_permissions: ["iam:PassRole", "cloudformation:CreateStack"], severity: "critical" },
  { id: "PE-017", method: "PassRole + Glue", description: "Create a Glue job with an admin role that executes arbitrary code.", required_permissions: ["iam:PassRole", "glue:CreateJob", "glue:StartJobRun"], severity: "high" },
  { id: "PE-018", method: "PassRole + SageMaker", description: "Create a SageMaker notebook with an admin role to execute code in a Jupyter environment.", required_permissions: ["iam:PassRole", "sagemaker:CreateNotebookInstance"], severity: "high" },
  { id: "PE-019", method: "PassRole + DataPipeline", description: "Create a Data Pipeline with an admin role that runs arbitrary commands.", required_permissions: ["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:ActivatePipeline"], severity: "high" },
  { id: "PE-020", method: "PassRole + CodeBuild", description: "Create a CodeBuild project with an admin role and run a build that executes privileged commands.", required_permissions: ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"], severity: "high" },
  { id: "PE-021", method: "PassRole + ECS", description: "Create an ECS task definition with an admin role and run the task.", required_permissions: ["iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"], severity: "high" },
  { id: "PE-022", method: "PassRole + SSM", description: "Send an SSM command to an instance with an admin role to execute privileged commands.", required_permissions: ["ssm:SendCommand", "ssm:StartSession"], severity: "high" },
  { id: "PE-023", method: "STS AssumeRole chain", description: "Chain multiple role assumptions to reach a high-privilege role that the current identity cannot directly assume.", required_permissions: ["sts:AssumeRole"], severity: "high" },
  { id: "PE-024", method: "EC2 SSRF to IMDS", description: "Exploit SSRF in an EC2 application to steal IAM role credentials from the metadata service.", required_permissions: ["(application vulnerability)"], severity: "critical" },
  { id: "PE-025", method: "Lambda environment variable theft", description: "Read Lambda function configuration to extract secrets from environment variables.", required_permissions: ["lambda:GetFunction"], severity: "high" },
  { id: "PE-026", method: "CodeStar CreateProject", description: "CodeStar creates a service role with broad permissions that can be leveraged for privilege escalation.", required_permissions: ["codestar:CreateProject"], severity: "high" },
  { id: "PE-027", method: "Cognito admin set user password", description: "Set the password of any Cognito user to take over their identity and access.", required_permissions: ["cognito-idp:AdminSetUserPassword"], severity: "high" },
  { id: "PE-028", method: "SSO CreateAccountAssignment", description: "Assign admin permission set to the current user in any account.", required_permissions: ["sso:CreateAccountAssignment"], severity: "critical" },
  { id: "PE-029", method: "Organizations CreateAccount", description: "Create a new AWS account where the attacker is automatically root.", required_permissions: ["organizations:CreateAccount"], severity: "critical" },
  { id: "PE-030", method: "CloudFormation StackSet", description: "Create a StackSet that deploys admin resources across all accounts in the organization.", required_permissions: ["cloudformation:CreateStackSet", "cloudformation:CreateStackInstances"], severity: "critical" }
];

export const AWS_PENTEST_RULES = {
  description: "AWS allows penetration testing of certain services without prior approval, as long as you follow their Acceptable Use Policy.",
  permitted_services: [
    "EC2 instances, NAT Gateways, ELBs",
    "RDS",
    "CloudFront",
    "Aurora",
    "API Gateway",
    "Lambda and Lambda Edge",
    "Lightsail",
    "Elastic Beanstalk"
  ],
  prohibited_activities: [
    "DNS zone walking via Route 53",
    "DoS, DDoS, or simulated DoS/DDoS attacks",
    "Port flooding",
    "Protocol flooding",
    "Request flooding (login, API)",
    "Testing third-party applications hosted on AWS without authorization"
  ],
  notes: [
    "No prior authorization required for permitted services since 2019",
    "Must follow AWS Customer Support Policy for Penetration Testing",
    "Automated scanning tools must be configured to not generate excessive load",
    "Report any vulnerabilities found in AWS infrastructure itself to AWS Security",
    "For prohibited activities, request authorization via AWS Support"
  ]
};

export const AWS_METADATA_ATTACKS = {
  imdsv1: {
    description: "IMDSv1 uses simple HTTP GET requests to 169.254.169.254 with no authentication. Any process on the instance can query it.",
    endpoints: [
      { path: "/latest/meta-data/", description: "Root of instance metadata" },
      { path: "/latest/meta-data/ami-id", description: "AMI ID used to launch the instance" },
      { path: "/latest/meta-data/hostname", description: "Private hostname" },
      { path: "/latest/meta-data/local-ipv4", description: "Private IP address" },
      { path: "/latest/meta-data/public-ipv4", description: "Public IP address" },
      { path: "/latest/meta-data/iam/security-credentials/", description: "List IAM role name" },
      { path: "/latest/meta-data/iam/security-credentials/ROLE_NAME", description: "Temporary IAM credentials (AccessKeyId, SecretAccessKey, Token)" },
      { path: "/latest/user-data", description: "User data script (may contain secrets)" },
      { path: "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", description: "Instance identity credentials" },
      { path: "/latest/dynamic/instance-identity/document", description: "Instance identity document (account ID, region, instance ID)" }
    ],
    exploitation: "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ to get the role name, then curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME to get the credentials.",
    ssrf_vectors: [
      "URL parameter: ?url=http://169.254.169.254/...",
      "Redirect: server returns 302 to http://169.254.169.254/...",
      "DNS rebinding: DNS returns 169.254.169.254 after initial check",
      "Header injection: Host: 169.254.169.254",
      "PDF/HTML renderer: <iframe src='http://169.254.169.254/...'>"
    ]
  },
  imdsv2: {
    description: "IMDSv2 requires a PUT request to get a session token, then uses the token in subsequent GET requests. Mitigates most SSRF attacks.",
    usage: [
      "TOKEN=$(curl -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')",
      "curl -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/"
    ],
    bypass_attempts: [
      { technique: "Downgrade to v1", description: "If IMDSv2 is optional (HttpTokens: optional), v1 still works. Ensure HttpTokens: required.", mitigation: "Set HttpTokens to required via aws ec2 modify-instance-metadata-options." },
      { technique: "Container bridge bypass", description: "Containers on the host network can reach IMDS. HttpPutResponseHopLimit=1 blocks this from containers with extra network hops.", mitigation: "Set HttpPutResponseHopLimit to 1." },
      { technique: "SSRF with PUT capability", description: "If the SSRF vulnerability allows arbitrary HTTP methods, the attacker can get a v2 token via PUT.", mitigation: "Use network segmentation and WAF rules to block SSRF. Implement IMDSv2 as defense in depth, not sole control." }
    ],
    enforcement: "aws ec2 modify-instance-metadata-options --instance-id i-xxx --http-tokens required --http-put-response-hop-limit 1 --http-endpoint enabled"
  }
};

export const AWS_SECURITY_SERVICES = [
  { service: "Security Hub", description: "Central dashboard aggregating findings from GuardDuty, Inspector, Macie, IAM Access Analyzer, Firewall Manager, and partner tools. Provides compliance checks against CIS, PCI DSS, and AWS Foundational Security Best Practices.", key_features: ["Automated compliance checks", "Cross-account finding aggregation", "Integration with 50+ partner tools", "Custom actions via EventBridge", "Finding deduplication and prioritization"] },
  { service: "Inspector", description: "Automated vulnerability scanning for EC2 instances, Lambda functions, and container images in ECR. Scans for software vulnerabilities (CVEs) and network exposure.", key_features: ["Agentless scanning for EC2", "Lambda function code scanning", "ECR container image scanning", "Risk-based prioritization with Inspector Score", "Integration with Security Hub"] },
  { service: "Macie", description: "Data security service that uses machine learning to discover, classify, and protect sensitive data in S3 (PII, financial data, credentials).", key_features: ["Automated sensitive data discovery", "Custom data identifiers", "S3 bucket inventory and security posture", "Finding export to Security Hub", "Cost optimization via sampling"] },
  { service: "Detective", description: "Security investigation service that analyzes CloudTrail, VPC Flow Logs, and GuardDuty findings to build a linked graph of security events for incident investigation.", key_features: ["Automatic data ingestion and graph modeling", "Entity profiling (users, roles, IPs)", "Finding investigation workflows", "Cross-account investigation", "ML-based anomaly detection"] },
  { service: "WAF", description: "Web Application Firewall that protects CloudFront, ALB, API Gateway, and AppSync from common web exploits (SQLi, XSS, DDoS).", key_features: ["Managed rule groups (AWS and marketplace)", "Custom rules with rate limiting", "Bot control", "Account takeover prevention", "Real-time metrics and logging"] },
  { service: "Shield", description: "DDoS protection service. Shield Standard is free and protects against common layer 3/4 attacks. Shield Advanced provides additional protection and 24/7 DDoS response team.", key_features: ["Always-on network flow monitoring", "Automatic attack mitigation", "Shield Advanced: DDoS cost protection", "Shield Advanced: 24/7 DDoS Response Team", "Health-based detection"] },
  { service: "Network Firewall", description: "Managed network firewall for VPCs. Provides stateful inspection, intrusion prevention (IPS), and web filtering using Suricata-compatible rules.", key_features: ["Stateful packet inspection", "Suricata-compatible IPS rules", "Domain name filtering", "TLS inspection", "Centralized management via Firewall Manager"] },
  { service: "Firewall Manager", description: "Central security management service for managing WAF rules, Shield Advanced protections, security groups, Network Firewall policies, and Route 53 DNS Firewall rules across an AWS Organization.", key_features: ["Cross-account policy management", "Automatic remediation of non-compliant resources", "Centralized WAF rule deployment", "Security group auditing", "Third-party firewall support"] },
  { service: "Config", description: "Configuration recording and compliance auditing service. Tracks all resource configuration changes and evaluates them against rules.", key_features: ["Continuous configuration recording", "150+ managed rules", "Custom rules via Lambda", "Conformance packs for compliance frameworks", "Remediation actions"] },
  { service: "Organizations + SCPs", description: "Account management and governance. Service Control Policies (SCPs) set permission guardrails across all accounts in the organization.", key_features: ["Multi-account management", "Service Control Policies", "Tag policies", "Backup policies", "Delegated administrator for security services"] },
  { service: "Control Tower", description: "Multi-account setup and governance service. Provides pre-configured guardrails and landing zone for new AWS environments.", key_features: ["Account factory for provisioning", "Preventive guardrails (SCPs)", "Detective guardrails (Config rules)", "Dashboard for compliance status", "Customizations for Control Tower (CfCT)"] },
  { service: "IAM Access Analyzer", description: "Analyzes resource policies to identify resources shared externally. Also generates least-privilege IAM policies from CloudTrail activity.", key_features: ["External access analysis", "Unused access analysis", "Policy generation from CloudTrail", "Policy validation", "Custom policy checks"] }
];
