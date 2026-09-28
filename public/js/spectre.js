// SPECTRE — Security Posture Evaluation, Cloud Threat Response & Enforcement
// Browser-based cloud security posture management platform for Darknode
// Copyright (c) 2026 Darknode-Official. All rights reserved.
//
// Operates in three postures (SCOUTING / DEFENSIVE / OFFENSIVE) via the shared
// core/tool-modes switcher — same mechanism every flagship uses.

import { mountModeSwitcher } from '/js/core/tool-modes.js';

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ============================================================================
// AWS SECURITY CHECKS (50)
// ============================================================================
const AWS_CHECKS = [
  // S3 (8)
  { id: 'AWS-S3-001', service: 'S3', name: 'Public bucket access', severity: 'CRITICAL', category: 'Storage', cis: '2.1.1', description: 'S3 bucket allows public read or write access via ACL or bucket policy', recommendation: 'Remove public access, enable S3 Block Public Access at account level', field: 'PublicAccessBlockConfiguration' },
  { id: 'AWS-S3-002', service: 'S3', name: 'Server-side encryption disabled', severity: 'HIGH', category: 'Storage', cis: '2.1.2', description: 'S3 bucket does not have default server-side encryption enabled', recommendation: 'Enable SSE-S3 or SSE-KMS default encryption on all buckets', field: 'ServerSideEncryptionConfiguration' },
  { id: 'AWS-S3-003', service: 'S3', name: 'Versioning not enabled', severity: 'MEDIUM', category: 'Storage', cis: '2.1.3', description: 'S3 bucket does not have versioning enabled for data protection', recommendation: 'Enable versioning to protect against accidental deletion', field: 'Versioning' },
  { id: 'AWS-S3-004', service: 'S3', name: 'Access logging disabled', severity: 'MEDIUM', category: 'Storage', cis: '2.1.4', description: 'S3 bucket does not have server access logging configured', recommendation: 'Enable access logging to a dedicated logging bucket', field: 'LoggingConfiguration' },
  { id: 'AWS-S3-005', service: 'S3', name: 'No lifecycle policy', severity: 'LOW', category: 'Storage', cis: '2.1.5', description: 'S3 bucket has no lifecycle rules for data management', recommendation: 'Configure lifecycle rules for cost optimization and compliance', field: 'LifecycleConfiguration' },
  { id: 'AWS-S3-006', service: 'S3', name: 'Permissive bucket ACL', severity: 'HIGH', category: 'Storage', cis: '2.1.6', description: 'Bucket ACL grants access to AllUsers or AuthenticatedUsers', recommendation: 'Use bucket policies instead of ACLs, disable ACLs', field: 'ACL' },
  { id: 'AWS-S3-007', service: 'S3', name: 'MFA delete not enabled', severity: 'MEDIUM', category: 'Storage', cis: '2.1.7', description: 'MFA delete is not enabled on versioned bucket', recommendation: 'Enable MFA delete on critical data buckets', field: 'MfaDelete' },
  { id: 'AWS-S3-008', service: 'S3', name: 'Cross-account access', severity: 'HIGH', category: 'Storage', cis: '2.1.8', description: 'Bucket policy allows access from external AWS accounts', recommendation: 'Review and restrict cross-account access to trusted accounts only', field: 'BucketPolicy' },
  // IAM (10)
  { id: 'AWS-IAM-001', service: 'IAM', name: 'Root account without MFA', severity: 'CRITICAL', category: 'Identity', cis: '1.5', description: 'Root account does not have MFA enabled', recommendation: 'Enable hardware MFA on root account immediately', field: 'MFADevices' },
  { id: 'AWS-IAM-002', service: 'IAM', name: 'Unused IAM credentials', severity: 'MEDIUM', category: 'Identity', cis: '1.12', description: 'IAM users have credentials not used in 90+ days', recommendation: 'Deactivate or remove unused credentials', field: 'PasswordLastUsed' },
  { id: 'AWS-IAM-003', service: 'IAM', name: 'Overprivileged IAM policies', severity: 'HIGH', category: 'Identity', cis: '1.16', description: 'IAM policies with Action:* or Resource:* (admin access)', recommendation: 'Apply least privilege principle, use service-specific permissions', field: 'PolicyDocument' },
  { id: 'AWS-IAM-004', service: 'IAM', name: 'No password policy', severity: 'HIGH', category: 'Identity', cis: '1.8', description: 'Account password policy is not configured or is weak', recommendation: 'Set minimum 14-char password with complexity requirements', field: 'PasswordPolicy' },
  { id: 'AWS-IAM-005', service: 'IAM', name: 'Access keys over 90 days', severity: 'MEDIUM', category: 'Identity', cis: '1.14', description: 'IAM users have access keys older than 90 days', recommendation: 'Rotate access keys every 90 days', field: 'AccessKeyAge' },
  { id: 'AWS-IAM-006', service: 'IAM', name: 'Inline policies attached', severity: 'MEDIUM', category: 'Identity', cis: '1.15', description: 'IAM users or roles have inline policies instead of managed policies', recommendation: 'Convert inline policies to managed policies for easier auditing', field: 'InlinePolicies' },
  { id: 'AWS-IAM-007', service: 'IAM', name: 'Wildcard permissions', severity: 'CRITICAL', category: 'Identity', cis: '1.22', description: 'IAM policies grant wildcard (*) permissions on sensitive services', recommendation: 'Replace wildcard with specific actions and resources', field: 'Actions' },
  { id: 'AWS-IAM-008', service: 'IAM', name: 'Cross-account role trust', severity: 'HIGH', category: 'Identity', cis: '1.20', description: 'IAM roles trust external AWS accounts without conditions', recommendation: 'Add ExternalId condition to cross-account role trust policies', field: 'AssumeRolePolicy' },
  { id: 'AWS-IAM-009', service: 'IAM', name: 'No MFA for console users', severity: 'HIGH', category: 'Identity', cis: '1.10', description: 'IAM users with console access do not have MFA enabled', recommendation: 'Require MFA for all console users via IAM policy', field: 'MFADevices' },
  { id: 'AWS-IAM-010', service: 'IAM', name: 'Unused IAM roles', severity: 'LOW', category: 'Identity', cis: '1.21', description: 'IAM roles not assumed in 90+ days', recommendation: 'Review and remove unused roles to reduce attack surface', field: 'RoleLastUsed' },
  // EC2 (8)
  { id: 'AWS-EC2-001', service: 'EC2', name: 'Open SSH security group', severity: 'CRITICAL', category: 'Compute', cis: '5.2', description: 'Security group allows SSH (port 22) from 0.0.0.0/0', recommendation: 'Restrict SSH to known IP ranges, use Systems Manager Session Manager', field: 'SecurityGroups' },
  { id: 'AWS-EC2-002', service: 'EC2', name: 'Open RDP security group', severity: 'CRITICAL', category: 'Compute', cis: '5.3', description: 'Security group allows RDP (port 3389) from 0.0.0.0/0', recommendation: 'Restrict RDP to known IP ranges, use VPN or bastion host', field: 'SecurityGroups' },
  { id: 'AWS-EC2-003', service: 'EC2', name: 'Unencrypted EBS volumes', severity: 'HIGH', category: 'Compute', cis: '2.2.1', description: 'EBS volumes are not encrypted at rest', recommendation: 'Enable EBS encryption by default in account settings', field: 'Encrypted' },
  { id: 'AWS-EC2-004', service: 'EC2', name: 'Public AMIs', severity: 'HIGH', category: 'Compute', cis: '2.3.1', description: 'Custom AMIs are shared publicly', recommendation: 'Make AMIs private, share only with trusted accounts', field: 'Public' },
  { id: 'AWS-EC2-005', service: 'EC2', name: 'IMDSv1 enabled', severity: 'HIGH', category: 'Compute', cis: '5.6', description: 'Instance Metadata Service v1 is enabled (SSRF risk)', recommendation: 'Require IMDSv2 with HttpTokens=required', field: 'MetadataOptions' },
  { id: 'AWS-EC2-006', service: 'EC2', name: 'Default VPC in use', severity: 'MEDIUM', category: 'Compute', cis: '5.4', description: 'Resources deployed in the default VPC', recommendation: 'Create custom VPCs with proper network segmentation', field: 'VpcId' },
  { id: 'AWS-EC2-007', service: 'EC2', name: 'Unrestricted egress', severity: 'MEDIUM', category: 'Compute', cis: '5.5', description: 'Security group allows all outbound traffic (0.0.0.0/0 all ports)', recommendation: 'Restrict egress to required destinations and ports', field: 'EgressRules' },
  { id: 'AWS-EC2-008', service: 'EC2', name: 'No detailed monitoring', severity: 'LOW', category: 'Compute', cis: '3.1', description: 'Instances do not have detailed monitoring enabled', recommendation: 'Enable detailed monitoring for 1-minute metrics', field: 'Monitoring' },
  // RDS (6)
  { id: 'AWS-RDS-001', service: 'RDS', name: 'Public access enabled', severity: 'CRITICAL', category: 'Database', cis: '2.3.2', description: 'RDS instance is publicly accessible', recommendation: 'Set PubliclyAccessible to false, use VPC endpoints', field: 'PubliclyAccessible' },
  { id: 'AWS-RDS-002', service: 'RDS', name: 'Storage not encrypted', severity: 'HIGH', category: 'Database', cis: '2.3.3', description: 'RDS storage encryption is disabled', recommendation: 'Enable encryption at rest with KMS key', field: 'StorageEncrypted' },
  { id: 'AWS-RDS-003', service: 'RDS', name: 'No automated backups', severity: 'HIGH', category: 'Database', cis: '2.3.4', description: 'Automated backups are disabled (retention period 0)', recommendation: 'Set backup retention to at least 7 days', field: 'BackupRetentionPeriod' },
  { id: 'AWS-RDS-004', service: 'RDS', name: 'Default port in use', severity: 'LOW', category: 'Database', cis: '2.3.5', description: 'RDS uses default port (3306, 5432, 1433)', recommendation: 'Use non-default ports to reduce automated scanning exposure', field: 'Port' },
  { id: 'AWS-RDS-005', service: 'RDS', name: 'No Multi-AZ deployment', severity: 'MEDIUM', category: 'Database', cis: '2.3.6', description: 'RDS instance is not deployed in Multi-AZ configuration', recommendation: 'Enable Multi-AZ for production databases', field: 'MultiAZ' },
  { id: 'AWS-RDS-006', service: 'RDS', name: 'Minor version auto-upgrade off', severity: 'LOW', category: 'Database', cis: '2.3.7', description: 'Automatic minor version upgrades are disabled', recommendation: 'Enable auto minor version upgrade for security patches', field: 'AutoMinorVersionUpgrade' },
  // CloudTrail (5)
  { id: 'AWS-CT-001', service: 'CloudTrail', name: 'CloudTrail disabled', severity: 'CRITICAL', category: 'Logging', cis: '3.1', description: 'CloudTrail is not enabled in the region', recommendation: 'Enable CloudTrail with multi-region trail', field: 'IsLogging' },
  { id: 'AWS-CT-002', service: 'CloudTrail', name: 'No log file validation', severity: 'HIGH', category: 'Logging', cis: '3.2', description: 'CloudTrail log file integrity validation is disabled', recommendation: 'Enable log file validation to detect tampering', field: 'LogFileValidationEnabled' },
  { id: 'AWS-CT-003', service: 'CloudTrail', name: 'Logs not encrypted', severity: 'HIGH', category: 'Logging', cis: '3.7', description: 'CloudTrail logs are not encrypted with KMS', recommendation: 'Configure SSE-KMS encryption for CloudTrail logs', field: 'KmsKeyId' },
  { id: 'AWS-CT-004', service: 'CloudTrail', name: 'Not multi-region', severity: 'HIGH', category: 'Logging', cis: '3.1', description: 'CloudTrail is not configured as multi-region trail', recommendation: 'Enable multi-region trail to capture all API calls', field: 'IsMultiRegionTrail' },
  { id: 'AWS-CT-005', service: 'CloudTrail', name: 'No S3 access logging', severity: 'MEDIUM', category: 'Logging', cis: '3.6', description: 'S3 bucket storing CloudTrail logs does not have access logging', recommendation: 'Enable access logging on the CloudTrail S3 bucket', field: 'S3BucketLogging' },
  // Lambda (4)
  { id: 'AWS-LM-001', service: 'Lambda', name: 'Publicly accessible function', severity: 'CRITICAL', category: 'Compute', cis: '5.7', description: 'Lambda function resource policy allows public invocation', recommendation: 'Remove public access, use API Gateway with auth', field: 'Policy' },
  { id: 'AWS-LM-002', service: 'Lambda', name: 'Overprivileged execution role', severity: 'HIGH', category: 'Compute', cis: '1.16', description: 'Lambda execution role has admin or wildcard permissions', recommendation: 'Apply least privilege to execution role', field: 'Role' },
  { id: 'AWS-LM-003', service: 'Lambda', name: 'Not in VPC', severity: 'MEDIUM', category: 'Compute', cis: '5.8', description: 'Lambda function is not deployed in a VPC', recommendation: 'Deploy in VPC for network isolation where needed', field: 'VpcConfig' },
  { id: 'AWS-LM-004', service: 'Lambda', name: 'Secrets in env vars', severity: 'CRITICAL', category: 'Compute', cis: '1.19', description: 'Environment variables contain potential secrets (API keys, passwords)', recommendation: 'Use AWS Secrets Manager or SSM Parameter Store', field: 'Environment' },
  // VPC (5)
  { id: 'AWS-VPC-001', service: 'VPC', name: 'Default VPC exists', severity: 'MEDIUM', category: 'Network', cis: '5.4', description: 'Default VPC has not been deleted', recommendation: 'Delete default VPC in unused regions, use custom VPCs', field: 'IsDefault' },
  { id: 'AWS-VPC-002', service: 'VPC', name: 'No VPC flow logs', severity: 'HIGH', category: 'Network', cis: '3.9', description: 'VPC flow logs are not enabled', recommendation: 'Enable VPC flow logs for network traffic visibility', field: 'FlowLogs' },
  { id: 'AWS-VPC-003', service: 'VPC', name: 'Unrestricted NACLs', severity: 'HIGH', category: 'Network', cis: '5.1', description: 'Network ACLs allow all inbound traffic', recommendation: 'Configure NACLs as additional defense layer', field: 'NetworkAcls' },
  { id: 'AWS-VPC-004', service: 'VPC', name: 'Peering without approval', severity: 'MEDIUM', category: 'Network', cis: '5.9', description: 'VPC peering connections to unknown accounts', recommendation: 'Review and approve all VPC peering connections', field: 'VpcPeeringConnections' },
  { id: 'AWS-VPC-005', service: 'VPC', name: 'No endpoint policies', severity: 'MEDIUM', category: 'Network', cis: '5.10', description: 'VPC endpoints have no restrictive policies', recommendation: 'Add endpoint policies to restrict service access', field: 'VpcEndpoints' },
  // KMS (4)
  { id: 'AWS-KMS-001', service: 'KMS', name: 'Key rotation disabled', severity: 'HIGH', category: 'Encryption', cis: '3.8', description: 'KMS customer-managed keys do not have automatic rotation', recommendation: 'Enable automatic key rotation (annual)', field: 'KeyRotationEnabled' },
  { id: 'AWS-KMS-002', service: 'KMS', name: 'Overly permissive key policy', severity: 'HIGH', category: 'Encryption', cis: '3.9', description: 'KMS key policy allows broad access', recommendation: 'Restrict key policy to specific IAM principals', field: 'KeyPolicy' },
  { id: 'AWS-KMS-003', service: 'KMS', name: 'Default AWS keys used', severity: 'MEDIUM', category: 'Encryption', cis: '3.10', description: 'Services use AWS-managed keys instead of CMK', recommendation: 'Create and use customer-managed KMS keys', field: 'KeyManager' },
  { id: 'AWS-KMS-004', service: 'KMS', name: 'Cross-account key access', severity: 'HIGH', category: 'Encryption', cis: '3.11', description: 'KMS key policy grants access to external accounts', recommendation: 'Review and restrict cross-account key access', field: 'KeyPolicy' },
];

// ============================================================================
// AZURE SECURITY CHECKS (40)
// ============================================================================
const AZURE_CHECKS = [
  // NSG (8)
  { id: 'AZ-NSG-001', service: 'NSG', name: 'Any-to-any inbound rule', severity: 'CRITICAL', category: 'Network', cis: '6.1', description: 'NSG rule allows all inbound traffic (source Any, destination Any)', recommendation: 'Replace with specific source/destination rules' },
  { id: 'AZ-NSG-002', service: 'NSG', name: 'SSH open to internet', severity: 'CRITICAL', category: 'Network', cis: '6.2', description: 'NSG allows SSH (port 22) from 0.0.0.0/0 or Internet', recommendation: 'Restrict SSH to bastion host or VPN IP ranges' },
  { id: 'AZ-NSG-003', service: 'NSG', name: 'RDP open to internet', severity: 'CRITICAL', category: 'Network', cis: '6.3', description: 'NSG allows RDP (port 3389) from Internet', recommendation: 'Use Azure Bastion or restrict to VPN ranges' },
  { id: 'AZ-NSG-004', service: 'NSG', name: 'No flow logs', severity: 'HIGH', category: 'Network', cis: '6.4', description: 'NSG flow logs are not enabled', recommendation: 'Enable NSG flow logs for traffic visibility' },
  { id: 'AZ-NSG-005', service: 'NSG', name: 'Missing service tags', severity: 'MEDIUM', category: 'Network', cis: '6.5', description: 'NSG rules use IP addresses instead of service tags', recommendation: 'Use Azure Service Tags for dynamic IP management' },
  { id: 'AZ-NSG-006', service: 'NSG', name: 'Unrestricted inbound ports', severity: 'HIGH', category: 'Network', cis: '6.6', description: 'NSG allows inbound on high-risk ports (445, 1433, 3306)', recommendation: 'Restrict database and SMB ports to known sources' },
  { id: 'AZ-NSG-007', service: 'NSG', name: 'No DDoS protection', severity: 'MEDIUM', category: 'Network', cis: '6.7', description: 'Azure DDoS Protection Standard is not enabled on VNet', recommendation: 'Enable DDoS Protection Standard on production VNets' },
  { id: 'AZ-NSG-008', service: 'NSG', name: 'Allow-all outbound', severity: 'MEDIUM', category: 'Network', cis: '6.8', description: 'NSG allows all outbound traffic without restrictions', recommendation: 'Implement egress filtering for sensitive workloads' },
  // Storage (6)
  { id: 'AZ-ST-001', service: 'Storage', name: 'Public blob access', severity: 'CRITICAL', category: 'Storage', cis: '3.1', description: 'Storage account allows anonymous public blob access', recommendation: 'Disable public blob access at account level' },
  { id: 'AZ-ST-002', service: 'Storage', name: 'No encryption at rest', severity: 'HIGH', category: 'Storage', cis: '3.2', description: 'Storage encryption uses Microsoft-managed keys only', recommendation: 'Use customer-managed keys (CMK) for sensitive data' },
  { id: 'AZ-ST-003', service: 'Storage', name: 'Shared keys exposed', severity: 'HIGH', category: 'Storage', cis: '3.3', description: 'Storage account access via shared access keys', recommendation: 'Disable shared key access, use Azure AD and RBAC' },
  { id: 'AZ-ST-004', service: 'Storage', name: 'No private endpoints', severity: 'HIGH', category: 'Storage', cis: '3.4', description: 'Storage account accessible over public internet', recommendation: 'Configure private endpoints and disable public access' },
  { id: 'AZ-ST-005', service: 'Storage', name: 'HTTPS-only disabled', severity: 'HIGH', category: 'Storage', cis: '3.5', description: 'Storage account allows HTTP (non-TLS) connections', recommendation: 'Enable Secure Transfer Required' },
  { id: 'AZ-ST-006', service: 'Storage', name: 'Soft delete off', severity: 'MEDIUM', category: 'Storage', cis: '3.6', description: 'Blob soft delete is not enabled for data recovery', recommendation: 'Enable soft delete with 14+ day retention' },
  // Key Vault (5)
  { id: 'AZ-KV-001', service: 'Key Vault', name: 'No soft delete', severity: 'HIGH', category: 'Encryption', cis: '8.1', description: 'Key Vault soft delete is not enabled', recommendation: 'Enable soft delete (now default for new vaults)' },
  { id: 'AZ-KV-002', service: 'Key Vault', name: 'Overprivileged access', severity: 'HIGH', category: 'Encryption', cis: '8.2', description: 'Key Vault access policies grant broad permissions', recommendation: 'Use RBAC model with specific role assignments' },
  { id: 'AZ-KV-003', service: 'Key Vault', name: 'No firewall rules', severity: 'HIGH', category: 'Encryption', cis: '8.3', description: 'Key Vault allows access from all networks', recommendation: 'Configure firewall rules and private endpoints' },
  { id: 'AZ-KV-004', service: 'Key Vault', name: 'Purge protection off', severity: 'MEDIUM', category: 'Encryption', cis: '8.4', description: 'Purge protection is not enabled', recommendation: 'Enable purge protection to prevent permanent deletion' },
  { id: 'AZ-KV-005', service: 'Key Vault', name: 'Expired secrets', severity: 'HIGH', category: 'Encryption', cis: '8.5', description: 'Key Vault contains expired secrets or certificates', recommendation: 'Rotate expired secrets and set expiration alerts' },
  // Azure AD (6)
  { id: 'AZ-AD-001', service: 'Azure AD', name: 'No MFA for admins', severity: 'CRITICAL', category: 'Identity', cis: '1.1', description: 'Global administrators do not have MFA enforced', recommendation: 'Enable MFA for all admin accounts via Conditional Access' },
  { id: 'AZ-AD-002', service: 'Azure AD', name: 'Guest user access', severity: 'MEDIUM', category: 'Identity', cis: '1.2', description: 'Guest users have access to directory resources', recommendation: 'Review guest access and apply least privilege' },
  { id: 'AZ-AD-003', service: 'Azure AD', name: 'Legacy auth protocols', severity: 'HIGH', category: 'Identity', cis: '1.3', description: 'Legacy authentication protocols (IMAP, POP3, SMTP) are allowed', recommendation: 'Block legacy auth via Conditional Access policy' },
  { id: 'AZ-AD-004', service: 'Azure AD', name: 'Risky sign-in policy off', severity: 'HIGH', category: 'Identity', cis: '1.4', description: 'Azure AD Identity Protection risky sign-in policy is disabled', recommendation: 'Enable and configure risky sign-in policies' },
  { id: 'AZ-AD-005', service: 'Azure AD', name: 'No conditional access', severity: 'HIGH', category: 'Identity', cis: '1.5', description: 'No Conditional Access policies configured', recommendation: 'Implement Conditional Access policies for zero trust' },
  { id: 'AZ-AD-006', service: 'Azure AD', name: 'PIM not configured', severity: 'MEDIUM', category: 'Identity', cis: '1.6', description: 'Privileged Identity Management is not configured for admin roles', recommendation: 'Enable PIM for just-in-time admin access' },
  // VM (5)
  { id: 'AZ-VM-001', service: 'VM', name: 'Public IP assigned', severity: 'HIGH', category: 'Compute', cis: '7.1', description: 'Virtual machine has a public IP address assigned', recommendation: 'Remove public IP, use Azure Bastion or Load Balancer' },
  { id: 'AZ-VM-002', service: 'VM', name: 'Unmanaged disks', severity: 'MEDIUM', category: 'Compute', cis: '7.2', description: 'VM uses unmanaged disks instead of managed disks', recommendation: 'Migrate to managed disks for better security and reliability' },
  { id: 'AZ-VM-003', service: 'VM', name: 'No disk encryption', severity: 'HIGH', category: 'Compute', cis: '7.3', description: 'OS and data disks are not encrypted', recommendation: 'Enable Azure Disk Encryption or SSE with CMK' },
  { id: 'AZ-VM-004', service: 'VM', name: 'No boot diagnostics', severity: 'LOW', category: 'Compute', cis: '7.4', description: 'Boot diagnostics are not enabled', recommendation: 'Enable boot diagnostics for troubleshooting' },
  { id: 'AZ-VM-005', service: 'VM', name: 'Outdated OS', severity: 'HIGH', category: 'Compute', cis: '7.5', description: 'VM runs an outdated or unsupported OS version', recommendation: 'Update to supported OS version with latest patches' },
  // App Service (5)
  { id: 'AZ-AS-001', service: 'App Service', name: 'HTTP allowed', severity: 'HIGH', category: 'Compute', cis: '9.1', description: 'App Service allows non-HTTPS traffic', recommendation: 'Enable HTTPS Only setting' },
  { id: 'AZ-AS-002', service: 'App Service', name: 'No managed identity', severity: 'MEDIUM', category: 'Compute', cis: '9.2', description: 'App Service does not use managed identity for auth', recommendation: 'Enable system-assigned or user-assigned managed identity' },
  { id: 'AZ-AS-003', service: 'App Service', name: 'TLS 1.0/1.1 allowed', severity: 'HIGH', category: 'Compute', cis: '9.3', description: 'App Service allows TLS 1.0 or 1.1 connections', recommendation: 'Set minimum TLS version to 1.2' },
  { id: 'AZ-AS-004', service: 'App Service', name: 'FTP enabled', severity: 'MEDIUM', category: 'Compute', cis: '9.4', description: 'FTP/FTPS deployment is enabled', recommendation: 'Disable FTP, use Azure DevOps or GitHub Actions' },
  { id: 'AZ-AS-005', service: 'App Service', name: 'Remote debugging on', severity: 'HIGH', category: 'Compute', cis: '9.5', description: 'Remote debugging is enabled in production', recommendation: 'Disable remote debugging after troubleshooting' },
  // SQL (5)
  { id: 'AZ-SQL-001', service: 'SQL', name: 'No auditing', severity: 'HIGH', category: 'Database', cis: '4.1', description: 'Azure SQL auditing is not enabled', recommendation: 'Enable auditing to Log Analytics or Storage Account' },
  { id: 'AZ-SQL-002', service: 'SQL', name: 'No threat detection', severity: 'HIGH', category: 'Database', cis: '4.2', description: 'Advanced Threat Protection is not enabled', recommendation: 'Enable Advanced Threat Protection for SQL' },
  { id: 'AZ-SQL-003', service: 'SQL', name: 'TDE off', severity: 'HIGH', category: 'Database', cis: '4.3', description: 'Transparent Data Encryption is disabled', recommendation: 'Enable TDE with customer-managed key' },
  { id: 'AZ-SQL-004', service: 'SQL', name: 'Firewall allows all Azure', severity: 'MEDIUM', category: 'Database', cis: '4.4', description: 'SQL firewall rule allows all Azure services', recommendation: 'Restrict to specific Azure VNets and IPs' },
  { id: 'AZ-SQL-005', service: 'SQL', name: 'No private endpoint', severity: 'HIGH', category: 'Database', cis: '4.5', description: 'SQL server accessible over public endpoint', recommendation: 'Configure private endpoint and disable public access' },
];

// ============================================================================
// GCP SECURITY CHECKS (35)
// ============================================================================
const GCP_CHECKS = [
  // Compute (7)
  { id: 'GCP-CE-001', service: 'Compute', name: 'Default service account', severity: 'HIGH', category: 'Compute', cis: '4.1', description: 'Instance uses default compute service account', recommendation: 'Create and use custom service accounts with least privilege' },
  { id: 'GCP-CE-002', service: 'Compute', name: 'Public IP assigned', severity: 'HIGH', category: 'Compute', cis: '4.2', description: 'Instance has an external IP address', recommendation: 'Remove external IP, use Cloud NAT for outbound' },
  { id: 'GCP-CE-003', service: 'Compute', name: 'Serial port enabled', severity: 'MEDIUM', category: 'Compute', cis: '4.3', description: 'Serial port access is enabled on instance', recommendation: 'Disable serial port access (serial-port-enable=false)' },
  { id: 'GCP-CE-004', service: 'Compute', name: 'OS Login disabled', severity: 'MEDIUM', category: 'Compute', cis: '4.4', description: 'OS Login is not enabled for SSH management', recommendation: 'Enable OS Login for centralized SSH key management' },
  { id: 'GCP-CE-005', service: 'Compute', name: 'No shielded VM', severity: 'MEDIUM', category: 'Compute', cis: '4.5', description: 'Instance does not use Shielded VM features', recommendation: 'Enable Secure Boot, vTPM, and Integrity Monitoring' },
  { id: 'GCP-CE-006', service: 'Compute', name: 'Legacy metadata endpoint', severity: 'HIGH', category: 'Compute', cis: '4.6', description: 'v0.1 and v1beta1 metadata endpoints are accessible', recommendation: 'Block legacy metadata API (disable-legacy-endpoints=true)' },
  { id: 'GCP-CE-007', service: 'Compute', name: 'No confidential computing', severity: 'LOW', category: 'Compute', cis: '4.7', description: 'Instance does not use Confidential VM for data-in-use encryption', recommendation: 'Enable Confidential VM for sensitive workloads' },
  // IAM (6)
  { id: 'GCP-IAM-001', service: 'IAM', name: 'Overprivileged service account', severity: 'HIGH', category: 'Identity', cis: '1.1', description: 'Service account has Owner or Editor role at project level', recommendation: 'Use predefined roles with minimum required permissions' },
  { id: 'GCP-IAM-002', service: 'IAM', name: 'User-managed SA keys', severity: 'HIGH', category: 'Identity', cis: '1.2', description: 'Service account uses user-managed keys instead of GCP-managed', recommendation: 'Use Workload Identity or GCP-managed keys' },
  { id: 'GCP-IAM-003', service: 'IAM', name: 'Primitive roles in use', severity: 'HIGH', category: 'Identity', cis: '1.3', description: 'Users or SAs assigned primitive roles (Owner/Editor/Viewer)', recommendation: 'Replace primitive roles with predefined roles' },
  { id: 'GCP-IAM-004', service: 'IAM', name: 'Domain-wide delegation', severity: 'CRITICAL', category: 'Identity', cis: '1.4', description: 'Service account has domain-wide delegation enabled', recommendation: 'Remove delegation unless strictly required, audit scope' },
  { id: 'GCP-IAM-005', service: 'IAM', name: 'No org policy', severity: 'MEDIUM', category: 'Identity', cis: '1.5', description: 'Organization policies not configured for security guardrails', recommendation: 'Implement org policies for resource location, SA key creation' },
  { id: 'GCP-IAM-006', service: 'IAM', name: 'Cross-project access', severity: 'HIGH', category: 'Identity', cis: '1.6', description: 'IAM bindings grant access across project boundaries', recommendation: 'Review and restrict cross-project IAM bindings' },
  // Cloud Storage (5)
  { id: 'GCP-GCS-001', service: 'Cloud Storage', name: 'Public bucket', severity: 'CRITICAL', category: 'Storage', cis: '5.1', description: 'Bucket is publicly accessible (allUsers or allAuthenticatedUsers)', recommendation: 'Remove public access, use signed URLs for sharing' },
  { id: 'GCP-GCS-002', service: 'Cloud Storage', name: 'Uniform access disabled', severity: 'MEDIUM', category: 'Storage', cis: '5.2', description: 'Bucket uses fine-grained ACLs instead of uniform access', recommendation: 'Enable uniform bucket-level access' },
  { id: 'GCP-GCS-003', service: 'Cloud Storage', name: 'No retention policy', severity: 'MEDIUM', category: 'Storage', cis: '5.3', description: 'No retention policy configured for compliance', recommendation: 'Set retention policy for regulatory compliance' },
  { id: 'GCP-GCS-004', service: 'Cloud Storage', name: 'No CMEK encryption', severity: 'MEDIUM', category: 'Storage', cis: '5.4', description: 'Bucket uses Google-managed encryption instead of CMEK', recommendation: 'Use Cloud KMS customer-managed encryption keys' },
  { id: 'GCP-GCS-005', service: 'Cloud Storage', name: 'allUsers/allAuthenticatedUsers', severity: 'CRITICAL', category: 'Storage', cis: '5.5', description: 'IAM binding grants access to allUsers or allAuthenticatedUsers', recommendation: 'Remove allUsers and allAuthenticatedUsers bindings' },
  // VPC (5)
  { id: 'GCP-VPC-001', service: 'VPC', name: 'Default network exists', severity: 'MEDIUM', category: 'Network', cis: '3.1', description: 'Default VPC network has not been deleted', recommendation: 'Delete default network, create custom VPC with proper subnets' },
  { id: 'GCP-VPC-002', service: 'VPC', name: 'No firewall logging', severity: 'HIGH', category: 'Network', cis: '3.2', description: 'Firewall rule logging is not enabled', recommendation: 'Enable logging on all firewall rules' },
  { id: 'GCP-VPC-003', service: 'VPC', name: 'SSH from 0.0.0.0/0', severity: 'CRITICAL', category: 'Network', cis: '3.3', description: 'Firewall rule allows SSH from any source', recommendation: 'Restrict SSH to known IP ranges, use IAP tunneling' },
  { id: 'GCP-VPC-004', service: 'VPC', name: 'No VPC flow logs', severity: 'HIGH', category: 'Network', cis: '3.4', description: 'VPC flow logs are not enabled on subnets', recommendation: 'Enable flow logs on all subnets for visibility' },
  { id: 'GCP-VPC-005', service: 'VPC', name: 'Legacy network', severity: 'HIGH', category: 'Network', cis: '3.5', description: 'Project uses legacy network without subnets', recommendation: 'Migrate to custom mode VPC with subnets' },
  // Cloud SQL (4)
  { id: 'GCP-SQL-001', service: 'Cloud SQL', name: 'Public IP enabled', severity: 'HIGH', category: 'Database', cis: '6.1', description: 'Cloud SQL instance has a public IP address', recommendation: 'Use private IP only, connect via Cloud SQL Proxy' },
  { id: 'GCP-SQL-002', service: 'Cloud SQL', name: 'No SSL enforcement', severity: 'HIGH', category: 'Database', cis: '6.2', description: 'SSL/TLS connections are not required', recommendation: 'Enable require_ssl flag on Cloud SQL instance' },
  { id: 'GCP-SQL-003', service: 'Cloud SQL', name: 'No automated backups', severity: 'HIGH', category: 'Database', cis: '6.3', description: 'Automated backups are not configured', recommendation: 'Enable automated backups with 7+ day retention' },
  { id: 'GCP-SQL-004', service: 'Cloud SQL', name: 'Authorized networks too broad', severity: 'HIGH', category: 'Database', cis: '6.4', description: 'Authorized networks include 0.0.0.0/0', recommendation: 'Restrict to specific IP ranges, use private IP' },
  // KMS (4)
  { id: 'GCP-KMS-001', service: 'KMS', name: 'No key rotation', severity: 'HIGH', category: 'Encryption', cis: '1.7', description: 'Cloud KMS key rotation is not configured', recommendation: 'Set automatic rotation period (90 days recommended)' },
  { id: 'GCP-KMS-002', service: 'KMS', name: 'Overly permissive IAM', severity: 'HIGH', category: 'Encryption', cis: '1.8', description: 'KMS key has overly broad IAM bindings', recommendation: 'Restrict key access to specific service accounts' },
  { id: 'GCP-KMS-003', service: 'KMS', name: 'Default encryption only', severity: 'MEDIUM', category: 'Encryption', cis: '1.9', description: 'Resources use Google-managed encryption instead of CMEK', recommendation: 'Use CMEK for sensitive data encryption' },
  { id: 'GCP-KMS-004', service: 'KMS', name: 'No separation of duties', severity: 'MEDIUM', category: 'Encryption', cis: '1.10', description: 'Same principal can administer and use encryption keys', recommendation: 'Separate key admin and key user roles' },
  // Logging (4)
  { id: 'GCP-LOG-001', service: 'Logging', name: 'No log sinks', severity: 'HIGH', category: 'Logging', cis: '2.1', description: 'No log sinks configured for long-term retention', recommendation: 'Create log sinks to Cloud Storage or BigQuery' },
  { id: 'GCP-LOG-002', service: 'Logging', name: 'No alert policies', severity: 'HIGH', category: 'Logging', cis: '2.2', description: 'No Cloud Monitoring alert policies configured', recommendation: 'Create alert policies for security-relevant events' },
  { id: 'GCP-LOG-003', service: 'Logging', name: 'Audit logs disabled', severity: 'CRITICAL', category: 'Logging', cis: '2.3', description: 'Data Access audit logs are not enabled', recommendation: 'Enable Data Access audit logs for all services' },
  { id: 'GCP-LOG-004', service: 'Logging', name: 'No log exclusions review', severity: 'MEDIUM', category: 'Logging', cis: '2.4', description: 'Log exclusion filters may hide security events', recommendation: 'Review log exclusions to ensure security logs are captured' },
];

// ============================================================================
// COMPLIANCE FRAMEWORKS
// ============================================================================
const COMPLIANCE_FRAMEWORKS = {
  cis: {
    name: 'CIS Benchmarks',
    controls: [
      { id: 'CIS-1.1', name: 'Maintain inventory of authorized software', category: 'Inventory' },
      { id: 'CIS-1.2', name: 'Ensure unauthorized software is removed', category: 'Inventory' },
      { id: 'CIS-2.1', name: 'Maintain inventory of network devices', category: 'Inventory' },
      { id: 'CIS-2.2', name: 'Ensure use of standard secure configurations', category: 'Configuration' },
      { id: 'CIS-3.1', name: 'Establish secure configurations for hardware', category: 'Configuration' },
      { id: 'CIS-3.2', name: 'Implement automated configuration monitoring', category: 'Configuration' },
      { id: 'CIS-4.1', name: 'Conduct regular vulnerability assessments', category: 'Vulnerability' },
      { id: 'CIS-4.2', name: 'Remediate vulnerabilities in timely manner', category: 'Vulnerability' },
      { id: 'CIS-5.1', name: 'Minimize administrative privileges', category: 'Access Control' },
      { id: 'CIS-5.2', name: 'Use multi-factor authentication', category: 'Access Control' },
      { id: 'CIS-5.3', name: 'Require strong passwords', category: 'Access Control' },
      { id: 'CIS-6.1', name: 'Maintain audit log management', category: 'Logging' },
      { id: 'CIS-6.2', name: 'Enable detailed logging on critical systems', category: 'Logging' },
      { id: 'CIS-7.1', name: 'Deploy email protection mechanisms', category: 'Email/Web' },
      { id: 'CIS-7.2', name: 'Deploy web application firewalls', category: 'Email/Web' },
      { id: 'CIS-8.1', name: 'Use centralized anti-malware management', category: 'Malware' },
      { id: 'CIS-8.2', name: 'Ensure automatic anti-malware updates', category: 'Malware' },
      { id: 'CIS-9.1', name: 'Control access to network ports', category: 'Network' },
      { id: 'CIS-9.2', name: 'Ensure only approved ports are accessible', category: 'Network' },
      { id: 'CIS-10.1', name: 'Ensure regular data backups', category: 'Recovery' },
      { id: 'CIS-10.2', name: 'Test data backup recovery procedures', category: 'Recovery' },
      { id: 'CIS-11.1', name: 'Maintain secure network configurations', category: 'Network' },
      { id: 'CIS-12.1', name: 'Deploy network boundary defenses', category: 'Perimeter' },
      { id: 'CIS-13.1', name: 'Implement data loss prevention', category: 'Data Protection' },
      { id: 'CIS-14.1', name: 'Segment network by sensitivity', category: 'Network' },
    ]
  },
  nist: {
    name: 'NIST 800-53',
    controls: [
      { id: 'AC-1', name: 'Access Control Policy and Procedures', category: 'Access Control' },
      { id: 'AC-2', name: 'Account Management', category: 'Access Control' },
      { id: 'AC-3', name: 'Access Enforcement', category: 'Access Control' },
      { id: 'AC-6', name: 'Least Privilege', category: 'Access Control' },
      { id: 'AU-2', name: 'Audit Events', category: 'Audit' },
      { id: 'AU-3', name: 'Content of Audit Records', category: 'Audit' },
      { id: 'AU-6', name: 'Audit Review, Analysis, and Reporting', category: 'Audit' },
      { id: 'CA-7', name: 'Continuous Monitoring', category: 'Assessment' },
      { id: 'CM-2', name: 'Baseline Configuration', category: 'Configuration' },
      { id: 'CM-6', name: 'Configuration Settings', category: 'Configuration' },
      { id: 'IA-2', name: 'Identification and Authentication', category: 'Identification' },
      { id: 'IA-5', name: 'Authenticator Management', category: 'Identification' },
      { id: 'IR-4', name: 'Incident Handling', category: 'Incident Response' },
      { id: 'IR-5', name: 'Incident Monitoring', category: 'Incident Response' },
      { id: 'RA-5', name: 'Vulnerability Scanning', category: 'Risk Assessment' },
      { id: 'SC-7', name: 'Boundary Protection', category: 'System Protection' },
      { id: 'SC-8', name: 'Transmission Confidentiality', category: 'System Protection' },
      { id: 'SC-13', name: 'Cryptographic Protection', category: 'System Protection' },
      { id: 'SI-2', name: 'Flaw Remediation', category: 'System Integrity' },
      { id: 'SI-4', name: 'Information System Monitoring', category: 'System Integrity' },
    ]
  },
  soc2: {
    name: 'SOC 2 Trust Criteria',
    controls: [
      { id: 'CC1.1', name: 'Control environment integrity', category: 'Common Criteria' },
      { id: 'CC2.1', name: 'Information and communication', category: 'Common Criteria' },
      { id: 'CC3.1', name: 'Risk assessment processes', category: 'Common Criteria' },
      { id: 'CC4.1', name: 'Monitoring activities', category: 'Common Criteria' },
      { id: 'CC5.1', name: 'Control activities selection', category: 'Common Criteria' },
      { id: 'CC6.1', name: 'Logical and physical access', category: 'Security' },
      { id: 'CC6.2', name: 'System credentials management', category: 'Security' },
      { id: 'CC6.3', name: 'Authorized access enforcement', category: 'Security' },
      { id: 'CC6.6', name: 'Encryption of data in transit', category: 'Security' },
      { id: 'CC6.7', name: 'Data movement restrictions', category: 'Security' },
      { id: 'CC7.1', name: 'Detection of unauthorized changes', category: 'Availability' },
      { id: 'CC7.2', name: 'Monitoring for anomalies', category: 'Availability' },
      { id: 'CC8.1', name: 'Change management process', category: 'Change Mgmt' },
      { id: 'CC9.1', name: 'Risk mitigation activities', category: 'Risk Mgmt' },
      { id: 'CC9.2', name: 'Vendor risk management', category: 'Risk Mgmt' },
    ]
  },
  pci: {
    name: 'PCI-DSS v4.0',
    controls: [
      { id: 'PCI-1', name: 'Install and maintain network security controls', category: 'Network' },
      { id: 'PCI-2', name: 'Apply secure configurations to all components', category: 'Configuration' },
      { id: 'PCI-3', name: 'Protect stored account data', category: 'Data Protection' },
      { id: 'PCI-4', name: 'Protect data with strong cryptography in transit', category: 'Encryption' },
      { id: 'PCI-5', name: 'Protect against malicious software', category: 'Malware' },
      { id: 'PCI-6', name: 'Develop and maintain secure systems', category: 'Development' },
      { id: 'PCI-7', name: 'Restrict access by business need-to-know', category: 'Access' },
      { id: 'PCI-8', name: 'Identify users and authenticate access', category: 'Identity' },
      { id: 'PCI-9', name: 'Restrict physical access to cardholder data', category: 'Physical' },
      { id: 'PCI-10', name: 'Log and monitor all access to components', category: 'Logging' },
      { id: 'PCI-11', name: 'Test security of systems and networks regularly', category: 'Testing' },
      { id: 'PCI-12', name: 'Support information security with policies', category: 'Governance' },
    ]
  },
  hipaa: {
    name: 'HIPAA Security Rule',
    controls: [
      { id: 'HIPAA-164.308(a)(1)', name: 'Security management process', category: 'Administrative' },
      { id: 'HIPAA-164.308(a)(3)', name: 'Workforce security', category: 'Administrative' },
      { id: 'HIPAA-164.308(a)(4)', name: 'Information access management', category: 'Administrative' },
      { id: 'HIPAA-164.308(a)(5)', name: 'Security awareness training', category: 'Administrative' },
      { id: 'HIPAA-164.308(a)(6)', name: 'Security incident procedures', category: 'Administrative' },
      { id: 'HIPAA-164.308(a)(7)', name: 'Contingency plan', category: 'Administrative' },
      { id: 'HIPAA-164.310(a)(1)', name: 'Facility access controls', category: 'Physical' },
      { id: 'HIPAA-164.310(d)(1)', name: 'Device and media controls', category: 'Physical' },
      { id: 'HIPAA-164.312(a)(1)', name: 'Access control', category: 'Technical' },
      { id: 'HIPAA-164.312(e)(1)', name: 'Transmission security', category: 'Technical' },
    ]
  }
};

// ============================================================================
// IAM SAMPLE POLICIES
// ============================================================================
const IAM_SAMPLES = {
  admin: {
    name: 'AdministratorAccess',
    policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }
  },
  readonly: {
    name: 'ReadOnlyAccess',
    policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ['s3:Get*', 's3:List*', 'ec2:Describe*', 'iam:Get*', 'iam:List*', 'cloudtrail:LookupEvents', 'logs:Get*', 'logs:Describe*'], Resource: '*' }] }
  },
  overprivileged: {
    name: 'OverprivilegedDev',
    policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ['s3:*', 'ec2:*', 'lambda:*', 'iam:PassRole', 'iam:CreateRole', 'iam:AttachRolePolicy', 'sts:AssumeRole'], Resource: '*' }, { Effect: 'Allow', Action: ['dynamodb:*', 'sqs:*', 'sns:*'], Resource: '*' }] }
  },
  s3full: {
    name: 'S3FullAccess',
    policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: ['arn:aws:s3:::*', 'arn:aws:s3:::*/*'] }] }
  },
  lambda: {
    name: 'LambdaExecution',
    policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'], Resource: 'arn:aws:logs:*:*:*' }, { Effect: 'Allow', Action: ['s3:GetObject', 's3:PutObject'], Resource: 'arn:aws:s3:::my-bucket/*' }, { Effect: 'Allow', Action: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Query'], Resource: 'arn:aws:dynamodb:*:*:table/my-table' }] }
  }
};

// ============================================================================
// TERRAFORM SAMPLE & CHECKS
// ============================================================================
const TF_SAMPLE = `# Darknode Cloud Infrastructure - Demo Config

resource "aws_s3_bucket" "data_store" {
  bucket = "darknode-data-2026"
  acl    = "public-read"

  tags = {
    Name = "DataStore"
  }
}

resource "aws_instance" "web_server" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.medium"

  associate_public_ip_address = true

  tags = {
    Name = "WebServer"
  }
}

resource "aws_security_group" "web_sg" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "lambda_role" {
  name = "lambda-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name   = "lambda-full-access"
  role   = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_db_instance" "database" {
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.medium"
  allocated_storage = 20
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}

resource "aws_ebs_volume" "data_vol" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}`;

const TF_CHECKS = [
  { pattern: /acl\s*=\s*"public-read"/, resource: 'aws_s3_bucket', issue: 'Public-read ACL on S3 bucket', severity: 'CRITICAL', fix: 'Remove acl or set to "private", use bucket policy for controlled access' },
  { pattern: /associate_public_ip_address\s*=\s*true/, resource: 'aws_instance', issue: 'Public IP on EC2 instance', severity: 'HIGH', fix: 'Set associate_public_ip_address = false, use NAT Gateway or ALB' },
  { pattern: /cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\]/, resource: 'aws_security_group', issue: 'Security group open to 0.0.0.0/0', severity: 'CRITICAL', fix: 'Restrict CIDR blocks to known IP ranges' },
  { pattern: /from_port\s*=\s*22/, resource: 'aws_security_group', issue: 'SSH port 22 exposed', severity: 'HIGH', fix: 'Restrict SSH to VPN/bastion IP ranges, or use SSM Session Manager' },
  { pattern: /protocol\s*=\s*"-1"/, resource: 'aws_security_group', issue: 'All protocols allowed in egress', severity: 'MEDIUM', fix: 'Restrict egress to specific protocols and ports' },
  { pattern: /Action\s*=\s*"\*"/, resource: 'aws_iam_role_policy', issue: 'Wildcard Action (*) in IAM policy', severity: 'CRITICAL', fix: 'Replace with specific actions following least privilege' },
  { pattern: /Resource\s*=\s*"\*"/, resource: 'aws_iam_role_policy', issue: 'Wildcard Resource (*) in IAM policy', severity: 'HIGH', fix: 'Scope resources to specific ARNs' },
  { pattern: /publicly_accessible\s*=\s*true/, resource: 'aws_db_instance', issue: 'RDS publicly accessible', severity: 'CRITICAL', fix: 'Set publicly_accessible = false, use VPC endpoints' },
  { pattern: /storage_encrypted\s*=\s*false/, resource: 'aws_db_instance', issue: 'RDS storage not encrypted', severity: 'HIGH', fix: 'Set storage_encrypted = true with KMS key' },
  { pattern: /encrypted\s*=\s*false/, resource: 'aws_ebs_volume', issue: 'EBS volume not encrypted', severity: 'HIGH', fix: 'Set encrypted = true, enable default EBS encryption' },
  { pattern: /skip_final_snapshot\s*=\s*true/, resource: 'aws_db_instance', issue: 'Final snapshot skipped on RDS deletion', severity: 'MEDIUM', fix: 'Set skip_final_snapshot = false for production databases' },
  { pattern: /instance_type\s*=\s*"t2\./, resource: 'aws_instance', issue: 'Previous-gen instance type (t2) lacks burstable credits', severity: 'LOW', fix: 'Upgrade to t3 or t3a instance family for better price-performance' },
  { pattern: /password\s*=\s*"[^"]*"/, resource: 'any', issue: 'Hardcoded password in config', severity: 'CRITICAL', fix: 'Use AWS Secrets Manager or SSM Parameter Store' },
  { pattern: /access_key\s*=\s*"[^"]*"/, resource: 'any', issue: 'Hardcoded access key in config', severity: 'CRITICAL', fix: 'Use IAM roles or environment variables' },
  { pattern: /secret_key\s*=\s*"[^"]*"/, resource: 'any', issue: 'Hardcoded secret key in config', severity: 'CRITICAL', fix: 'Use IAM roles or environment variables' },
];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
function _spSevColor(sev) {
  if (sev === 'CRITICAL') return '#dc2626';
  if (sev === 'HIGH') return '#f97316';
  if (sev === 'MEDIUM') return '#eab308';
  if (sev === 'LOW') return '#22c55e';
  return '#64748b';
}
function _spSevBg(sev) {
  if (sev === 'CRITICAL') return 'rgba(220,38,38,.12)';
  if (sev === 'HIGH') return 'rgba(249,115,22,.12)';
  if (sev === 'MEDIUM') return 'rgba(234,179,8,.12)';
  if (sev === 'LOW') return 'rgba(34,197,94,.12)';
  return 'rgba(100,116,139,.1)';
}
function _spStatusColor(s) {
  if (s === 'FAIL') return '#dc2626';
  if (s === 'WARN') return '#f97316';
  if (s === 'PASS') return '#22c55e';
  return '#64748b';
}
function _spPct(pass, total) { return total ? Math.round((pass / total) * 100) : 0; }

// ============================================================================
// SELF-ASSESSMENT ANSWER STORE
// ============================================================================
// Spectre does not connect to any cloud account. Every check status comes from
// the user's own answer to that check (Pass / Fail / N/A), persisted locally.
// Check names describe the misconfiguration, so "Pass" means the problem is not
// present and "Fail" means it is. Unanswered checks are never counted.
var _SP_ANS_KEY = 'darknode.spectre.answers.v1';
var _SP_HIST_KEY = 'darknode.spectre.history.v1';
var _spAnswers = null;
function _spLoadAnswers() {
  if (_spAnswers) return _spAnswers;
  _spAnswers = {};
  try {
    var raw = localStorage.getItem(_SP_ANS_KEY);
    var obj = raw ? JSON.parse(raw) : null;
    if (obj && typeof obj === 'object') _spAnswers = obj;
  } catch (e) { _spAnswers = {}; }
  return _spAnswers;
}
function _spGetAnswer(key) { return _spLoadAnswers()[key] || ''; }
function _spSetAnswer(key, val) {
  var a = _spLoadAnswers();
  if (val) a[key] = val; else delete a[key];
  try { localStorage.setItem(_SP_ANS_KEY, JSON.stringify(a)); } catch (e) { /* storage unavailable: keep in memory */ }
  _spRecordHistory();
}
function _spClearAnswers(prefixTest) {
  var a = _spLoadAnswers();
  Object.keys(a).forEach(function (k) { if (prefixTest(k)) delete a[k]; });
  try { localStorage.setItem(_SP_ANS_KEY, JSON.stringify(a)); } catch (e) { /* ignore */ }
  _spRecordHistory();
}
// Status for a cloud check: PASS / FAIL / N/A from the answer, else UNANSWERED.
function _spCheckStatus(check) {
  var v = _spGetAnswer(check.id);
  if (v === 'PASS' || v === 'FAIL') return v;
  if (v === 'NA') return 'N/A';
  return 'UNANSWERED';
}
function _spPlaceholderResource(check) {
  return '<your-' + check.service.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '>';
}
function _spCheckRow(check) {
  return {
    id: check.id, service: check.service, name: check.name,
    severity: check.severity, category: check.category,
    cis: check.cis, description: check.description,
    recommendation: check.recommendation, field: check.field || '',
    status: _spCheckStatus(check),
    resource: _spPlaceholderResource(check)
  };
}
// Scored results for one provider: only checks answered Pass or Fail.
function _spResultsFor(checks) {
  return checks.map(_spCheckRow).filter(function (r) { return r.status === 'PASS' || r.status === 'FAIL'; });
}
function _spAnsweredCount(checks) {
  return checks.filter(function (ch) { return !!_spGetAnswer(ch.id); }).length;
}
// Compliance control status from the user's answer (pass / partial / fail / na) or '' if unanswered.
function _spControlStatus(fwKey, ct) { return _spGetAnswer('cmp:' + fwKey + ':' + ct.id); }

// One score point per day, recorded whenever answers change, so Risk Trends
// shows the user's own history rather than invented data.
function _spRecordHistory() {
  try {
    var all = _SP_CLOUDS.reduce(function (acc, pair) { return acc.concat(_spResultsFor(pair[1])); }, []);
    if (!all.length) return;
    var point = { overall: _spPct(all.filter(function (r) { return r.status === 'PASS'; }).length, all.length) };
    _SP_CLOUDS.forEach(function (pair) {
      var rows = _spResultsFor(pair[1]);
      point[pair[0]] = rows.length ? _spPct(rows.filter(function (r) { return r.status === 'PASS'; }).length, rows.length) : null;
    });
    var raw = localStorage.getItem(_SP_HIST_KEY);
    var hist = raw ? JSON.parse(raw) : {};
    if (!hist || typeof hist !== 'object') hist = {};
    hist[new Date().toISOString().slice(0, 10)] = point;
    var days = Object.keys(hist).sort();
    while (days.length > 60) { delete hist[days.shift()]; }
    localStorage.setItem(_SP_HIST_KEY, JSON.stringify(hist));
  } catch (e) { /* storage unavailable: no history */ }
}
function _spLoadHistory() {
  try {
    var raw = localStorage.getItem(_SP_HIST_KEY);
    var hist = raw ? JSON.parse(raw) : {};
    if (!hist || typeof hist !== 'object') return [];
    return Object.keys(hist).sort().map(function (d) { return { date: d, p: hist[d] }; });
  } catch (e) { return []; }
}

function _spRunTfScan(hcl) {
  var findings = [];
  var lines = hcl.split('\n');
  TF_CHECKS.forEach(function(check) {
    for (var i = 0; i < lines.length; i++) {
      if (check.pattern.test(lines[i])) {
        findings.push({ line: i + 1, lineText: lines[i].trim(), resource: check.resource, issue: check.issue, severity: check.severity, fix: check.fix });
      }
    }
  });
  return findings;
}

function _spAnalyzeIAM(policy) {
  var findings = [];
  var statements = Array.isArray(policy.Statement) ? policy.Statement : [policy.Statement];
  statements.forEach(function(stmt, idx) {
    var actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
    var resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
    actions.forEach(function(action) {
      if (action === '*') {
        findings.push({ severity: 'CRITICAL', finding: 'Wildcard Action (*) grants full access to all AWS services', statement: idx + 1, recommendation: 'Replace with specific service actions' });
      } else if (action.endsWith(':*')) {
        var svc = action.split(':')[0];
        var dangerous = ['iam', 's3', 'ec2', 'lambda', 'sts', 'kms', 'organizations'];
        if (dangerous.indexOf(svc) >= 0) {
          findings.push({ severity: 'HIGH', finding: 'Full access to ' + svc + ' service (' + action + ')', statement: idx + 1, recommendation: 'Restrict to specific ' + svc + ' actions needed' });
        }
      }
      if (action === 'iam:PassRole' || action === 'iam:CreateRole' || action === 'iam:AttachRolePolicy') {
        findings.push({ severity: 'HIGH', finding: 'Privilege escalation risk: ' + action, statement: idx + 1, recommendation: 'Restrict with resource conditions or remove' });
      }
      if (action === 'sts:AssumeRole') {
        findings.push({ severity: 'MEDIUM', finding: 'Role assumption allowed: ' + action, statement: idx + 1, recommendation: 'Scope to specific role ARNs in Resource' });
      }
    });
    resources.forEach(function(resource) {
      if (resource === '*') {
        findings.push({ severity: 'HIGH', finding: 'Wildcard Resource (*) allows access to all resources', statement: idx + 1, recommendation: 'Scope to specific resource ARNs' });
      }
    });
  });
  return findings;
}

function _spBuildPermMatrix(policy) {
  var services = {};
  var statements = Array.isArray(policy.Statement) ? policy.Statement : [policy.Statement];
  statements.forEach(function(stmt) {
    if (stmt.Effect !== 'Allow') return;
    var actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
    actions.forEach(function(action) {
      if (action === '*') {
        ['iam', 's3', 'ec2', 'lambda', 'dynamodb', 'rds', 'cloudformation', 'cloudwatch', 'logs', 'kms', 'sts', 'sns', 'sqs'].forEach(function(s) { services[s] = 'Admin'; });
      } else {
        var parts = action.split(':');
        var svc = parts[0];
        var act = parts[1] || '';
        if (!services[svc]) services[svc] = 'Read';
        if (act === '*' || act.startsWith('Create') || act.startsWith('Put') || act.startsWith('Delete') || act.startsWith('Update') || act.startsWith('Attach') || act.startsWith('Detach')) {
          services[svc] = services[svc] === 'Admin' ? 'Admin' : 'Write';
        }
        if (act === '*') services[svc] = 'Admin';
      }
    });
  });
  return services;
}

// ============================================================================
// POSTURE SNAPSHOT (built from the user's checklist answers)
// ============================================================================
var _SP_CLOUDS = [['AWS', AWS_CHECKS], ['Azure', AZURE_CHECKS], ['GCP', GCP_CHECKS]];
var _SP_SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
var _SP_CLOUD_ORDER = { AWS: 0, Azure: 1, GCP: 2 };
function _spBuildSnapshot() {
  var out = [];
  _SP_CLOUDS.forEach(function (pair) {
    pair[1].forEach(function (ch) {
      var row = _spCheckRow(ch);
      row.cloud = pair[0];
      out.push(row);
    });
  });
  return out;
}
// Short "based on your answers" line shown on every snapshot-derived tab.
function _spAnswerNote(snap) {
  var answered = snap.filter(function (r) { return r.status !== 'UNANSWERED'; }).length;
  return '<p class="sp-sub sp-answer-note">Based on your checklist answers: <b>' + answered + ' of ' + snap.length + '</b> checks answered. Spectre does not connect to your cloud accounts; answer checks in the AWS, Azure and GCP tabs.</p>';
}

// Internet-exposure classifier used by the Attack Surface tab.
function _spClassifyExposure(item) {
  var t = (item.name + ' ' + (item.description || '') + ' ' + (item.field || '')).toLowerCase();
  if (/ssh/.test(t) && /0\.0\.0\.0|internet|\bany\b|open/.test(t)) return { type: 'Exposed SSH (22)', why: 'SSH is reachable from the public internet, a prime target for credential brute-force and exploit attempts.' };
  if (/rdp/.test(t) && /0\.0\.0\.0|internet|\bany\b|open/.test(t)) return { type: 'Exposed RDP (3389)', why: 'RDP is reachable from the internet, a leading ransomware entry vector.' };
  if (/public invocation|publicly accessible function/.test(t)) return { type: 'Public function invoke', why: 'The function can be invoked anonymously from the internet with no authentication.' };
  if (/public ami|shared publicly/.test(t)) return { type: 'Public image share', why: 'A machine image is shared publicly and may leak baked-in secrets or configuration.' };
  if (/public ip|external ip/.test(t)) return { type: 'Public IP address', why: 'The resource has a routable public IP and is directly reachable from the internet.' };
  if (/public bucket|public blob|public-read|public read or write|allusers|allauthenticatedusers|permissive bucket acl|anonymous public/.test(t)) return { type: 'Public data exposure', why: 'Stored data is readable (or writable) from the public internet without authentication.' };
  if (/no private endpoint|accessible over public|public endpoint|public internet|access from all networks|all networks/.test(t)) return { type: 'Public service endpoint', why: 'The service is published on a public endpoint instead of a private link.' };
  if (/0\.0\.0\.0\/0|any-to-any|all inbound|from internet|high-risk ports|authorized networks include|unrestricted nacl/.test(t)) return { type: 'Open network ingress', why: 'Network controls accept inbound traffic from any source address (0.0.0.0/0).' };
  if (/publicly accessible/.test(t)) return { type: 'Public data exposure', why: 'The resource is publicly accessible from the internet.' };
  return null;
}

// Effort estimate used to curate the Remediation Plan.
function _spEffort(item) {
  var t = (item.name + ' ' + (item.description || '')).toLowerCase();
  if (/private endpoint|private link|multi-az|multi-region|conditional access|\bpim\b|migrate|legacy network|delete default|custom vpc|network segmentation|workload identity|shielded vm|confidential/.test(t)) return 'High';
  if (/encrypt|encryption|logging|log file|flow logs|versioning|rotation|https|\btls\b|soft delete|purge protection|backup|monitoring|auditing|\btde\b|boot diagnostics/.test(t)) return 'Low';
  return 'Medium';
}

// Curated remediation snippets ({R} = resource). Unmapped checks fall back to a
// concrete per-cloud command scaffold built from the check's own recommendation.
var _SP_REMEDIATION = {
  'AWS-S3-001': 'aws s3api put-public-access-block --bucket {R} \\\n  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true',
  'AWS-S3-002': 'aws s3api put-bucket-encryption --bucket {R} \\\n  --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}\'',
  'AWS-S3-003': 'aws s3api put-bucket-versioning --bucket {R} --versioning-configuration Status=Enabled',
  'AWS-S3-006': 'aws s3api put-bucket-acl --bucket {R} --acl private\naws s3api put-bucket-ownership-controls --bucket {R} \\\n  --ownership-controls \'{"Rules":[{"ObjectOwnership":"BucketOwnerEnforced"}]}\'',
  'AWS-IAM-001': '# Sign in as root, open IAM > Security credentials, and assign a hardware MFA device.\naws iam get-account-summary --query \'SummaryMap.AccountMFAEnabled\'',
  'AWS-IAM-003': '# Scope the policy to specific actions/resources, then publish a new default version:\naws iam create-policy-version --policy-arn <policy-arn> --set-as-default \\\n  --policy-document file://least-privilege.json',
  'AWS-IAM-004': 'aws iam update-account-password-policy --minimum-password-length 14 \\\n  --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters',
  'AWS-IAM-007': '# Replace wildcard actions with explicit ones, then set as the default version:\naws iam create-policy-version --policy-arn <policy-arn> --set-as-default \\\n  --policy-document file://scoped-policy.json',
  'AWS-EC2-001': 'aws ec2 revoke-security-group-ingress --group-id {R} --protocol tcp --port 22 --cidr 0.0.0.0/0',
  'AWS-EC2-002': 'aws ec2 revoke-security-group-ingress --group-id {R} --protocol tcp --port 3389 --cidr 0.0.0.0/0',
  'AWS-EC2-003': 'aws ec2 enable-ebs-encryption-by-default\naws ec2 get-ebs-encryption-by-default',
  'AWS-EC2-005': 'aws ec2 modify-instance-metadata-options --instance-id {R} \\\n  --http-tokens required --http-endpoint enabled',
  'AWS-RDS-001': 'aws rds modify-db-instance --db-instance-identifier {R} --no-publicly-accessible --apply-immediately',
  'AWS-RDS-002': '# Encryption is fixed at creation. Snapshot, copy with a KMS key, then restore:\naws rds copy-db-snapshot --source-db-snapshot-identifier <snap> \\\n  --target-db-snapshot-identifier {R}-enc --kms-key-id <kms-key>',
  'AWS-CT-001': 'aws cloudtrail create-trail --name org-trail --s3-bucket-name <log-bucket> --is-multi-region-trail\naws cloudtrail start-logging --name org-trail',
  'AWS-CT-002': 'aws cloudtrail update-trail --name org-trail --enable-log-file-validation',
  'AWS-LM-001': 'aws lambda remove-permission --function-name {R} --statement-id <public-statement-id>',
  'AWS-KMS-001': 'aws kms enable-key-rotation --key-id {R}',
  'AWS-VPC-002': 'aws ec2 create-flow-logs --resource-type VPC --resource-ids {R} \\\n  --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /vpc/flowlogs',
  'AZ-NSG-001': 'az network nsg rule delete -g <rg> --nsg-name {R} -n allow-any-any',
  'AZ-NSG-002': 'az network nsg rule update -g <rg> --nsg-name {R} -n Allow-SSH \\\n  --source-address-prefixes <bastion-cidr> --access Allow',
  'AZ-NSG-003': 'az network nsg rule update -g <rg> --nsg-name {R} -n Allow-RDP \\\n  --source-address-prefixes <admin-cidr> --access Allow',
  'AZ-ST-001': 'az storage account update -n {R} --allow-blob-public-access false',
  'AZ-ST-004': 'az storage account update -n {R} --default-action Deny\naz storage account network-rule add -n {R} --vnet-name <vnet> --subnet <subnet>',
  'AZ-ST-005': 'az storage account update -n {R} --https-only true',
  'AZ-KV-003': 'az keyvault update -n {R} --default-action Deny\naz keyvault network-rule add -n {R} --subnet <subnet-id>',
  'AZ-AD-001': '# Create a Conditional Access policy in Entra ID that requires MFA for all\n# privileged directory roles (Global Administrator and equivalents).',
  'AZ-VM-001': 'az network nic ip-config update -g <rg> --nic-name <nic> -n ipconfig1 --remove publicIpAddress\naz network public-ip delete -g <rg> -n {R}',
  'AZ-SQL-001': 'az sql server audit-policy update -g <rg> -n {R} --state Enabled \\\n  --log-analytics-target-state Enabled --log-analytics-workspace-resource-id <ws-id>',
  'AZ-SQL-003': 'az sql db tde set -g <rg> -s {R} -d <db> --status Enabled',
  'AZ-SQL-005': 'az sql server update -g <rg> -n {R} --set publicNetworkAccess=Disabled',
  'GCP-CE-002': 'gcloud compute instances delete-access-config {R} --access-config-name "External NAT" --zone <zone>',
  'GCP-GCS-001': 'gsutil iam ch -d allUsers gs://{R}\ngsutil iam ch -d allAuthenticatedUsers gs://{R}',
  'GCP-GCS-005': 'gsutil iam ch -d allUsers gs://{R}\ngsutil iam ch -d allAuthenticatedUsers gs://{R}',
  'GCP-VPC-003': 'gcloud compute firewall-rules update {R} --source-ranges=10.0.0.0/8',
  'GCP-SQL-001': 'gcloud sql instances patch {R} --no-assign-ip',
  'GCP-SQL-002': 'gcloud sql instances patch {R} --require-ssl',
  'GCP-SQL-004': 'gcloud sql instances patch {R} --authorized-networks=<office-cidr>',
  'GCP-KMS-001': 'gcloud kms keys update {R} --keyring=<keyring> --location=<location> \\\n  --rotation-period=90d --next-rotation-time=$(date -u -d "+90 days" +%Y-%m-%dT%H:%M:%SZ)',
  'GCP-IAM-004': '# Remove domain-wide delegation from the service account in the Admin console\n# (Security > API controls) unless strictly required, then audit its OAuth scopes.',
  'GCP-LOG-003': '# Enable Data Access audit logs for all services via the IAM audit config:\ngcloud projects get-iam-policy <project> --format=json > policy.json\n# add an auditConfigs block for allServices, then:\ngcloud projects set-iam-policy <project> policy.json'
};
function _spCliLang(cloud) { return cloud === 'AWS' ? 'aws-cli' : cloud === 'Azure' ? 'az-cli' : 'gcloud'; }
function _spCliGroup(item) {
  var m = { S3: 's3api', IAM: 'iam', EC2: 'ec2', RDS: 'rds', CloudTrail: 'cloudtrail', Lambda: 'lambda', VPC: 'ec2', KMS: 'kms', NSG: 'network nsg', Storage: 'storage account', 'Key Vault': 'keyvault', 'Azure AD': 'ad', VM: 'vm', 'App Service': 'webapp', SQL: 'sql', Compute: 'compute instances', 'Cloud Storage': 'storage', 'Cloud SQL': 'sql', Logging: 'logging' };
  return m[item.service] || item.service.toLowerCase();
}
function _spRemediationSnippet(item) {
  var code = _SP_REMEDIATION[item.id];
  if (!code) {
    var tool = item.cloud === 'AWS' ? 'aws' : item.cloud === 'Azure' ? 'az' : 'gcloud';
    code = '# ' + item.id + ' — ' + item.name + '\n# ' + item.recommendation + '\n# Target: ' + item.resource + '\n' + tool + ' ' + _spCliGroup(item) + ' --help   # locate the update/modify call, then apply the fix above';
  }
  return { lang: _spCliLang(item.cloud), code: code.split('{R}').join(item.resource) };
}

function _spSparkline(values, w, h, color) {
  var step = w / (values.length - 1);
  var pts = values.map(function (v, i) { return (i * step).toFixed(1) + ',' + (h - (v / 100) * h).toFixed(1); });
  var area = 'M0,' + h + ' L' + pts.join(' L') + ' L' + w + ',' + h + ' Z';
  return '<svg class="sp-spark" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' +
    '<path d="' + area + '" fill="' + color + '" opacity="0.12"/>' +
    '<polyline points="' + pts.join(' ') + '" fill="none" stroke="' + color + '" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>' +
    '</svg>';
}

// Small stat tile used by Attack Surface and Remediation Plan.
function _spStatTile(n, label, color) {
  return '<div class="sp-stat-tile"><span class="sp-stat-n" style="color:' + color + '">' + esc(n) + '</span><span class="sp-stat-l">' + esc(label) + '</span></div>';
}

// Clipboard copy with an inline "Copied" affordance (no native dialogs).
function _spFallbackCopy(text) {
  var ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.focus(); ta.select();
  try { document.execCommand('copy'); } catch (e) { /* ignore */ }
  document.body.removeChild(ta);
}
function _spCopyText(text, btn) {
  var done = function () {
    var old = btn.getAttribute('data-label') || 'Copy';
    btn.textContent = 'Copied'; btn.classList.add('sp-copied');
    var id = setTimeout(function () { btn.textContent = old; btn.classList.remove('sp-copied'); }, 1500);
    (window._spectreTimers = window._spectreTimers || []).push(id);
  };
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { _spFallbackCopy(text); done(); });
    } else { _spFallbackCopy(text); done(); }
  } catch (e) { try { _spFallbackCopy(text); done(); } catch (e2) { /* ignore */ } }
}

// ============================================================================
// RENDER FUNCTIONS
// ============================================================================
var _spActiveTab = 'dashboard';
var _spTfFindings = null;
var _spTfSource = '';
var _spIamFindings = null;
var _spIamMatrix = null;
var _spSelectedPolicy = null;
var _spAuditFilter = { service: '', severity: '', status: '' };
var _spComplianceTab = 'cis';
var _spInterval = null;
var _spRemedEffort = '';
var _spExplorer = { cloud: '', severity: '', status: '', q: '' };
var _spAttackScenario = '';

// Full tab list. Each tab declares which operational postures it belongs to via
// `modes` (a subset of scouting/defensive/offensive). A tab with no `modes` is
// mode-agnostic and shows in every posture. The core/tool-modes switcher filters
// this list to the active posture and re-tints the console.
//   - dashboard          — agnostic overview (always shown)
//   - aws/azure/gcp/iam/compliance/terraform/remediate/trends — CSPM & hardening
//     work, ['defensive']
//   - surface, explorer  — inventory / exposure views useful for recon too,
//     ['scouting','defensive']
//   - recon (NEW)        — outside-in external attack-surface enumeration,
//     ['scouting']
//   - attackpath (NEW)   — simulated attack-path / privilege-escalation chains,
//     ['offensive']
function _spBuildTabs() {
  return [
    { id: 'dashboard', label: 'Posture Dashboard' },
    { id: 'recon', label: 'Attack Surface Recon', modes: ['scouting'] },
    { id: 'aws', label: 'AWS Audit', modes: ['defensive'] },
    { id: 'azure', label: 'Azure Audit', modes: ['defensive'] },
    { id: 'gcp', label: 'GCP Audit', modes: ['defensive'] },
    { id: 'iam', label: 'IAM Analyzer', modes: ['defensive'] },
    { id: 'compliance', label: 'Compliance', modes: ['defensive'] },
    { id: 'terraform', label: 'Terraform Scanner', modes: ['defensive'] },
    { id: 'surface', label: 'Attack Surface', modes: ['scouting', 'defensive'] },
    { id: 'attackpath', label: 'Attack Paths', modes: ['offensive'] },
    { id: 'remediate', label: 'Remediation Plan', modes: ['defensive'] },
    { id: 'trends', label: 'Risk Trends', modes: ['defensive'] },
    { id: 'explorer', label: 'Findings Explorer', modes: ['scouting', 'defensive'] }
  ];
}

function _spRouteContent(id, c) {
  if (id === 'dashboard') _spRenderDashboard(c);
  else if (id === 'recon') _spRenderRecon(c);
  else if (id === 'aws') _spRenderAudit(c, 'AWS', AWS_CHECKS);
  else if (id === 'azure') _spRenderAudit(c, 'Azure', AZURE_CHECKS);
  else if (id === 'gcp') _spRenderAudit(c, 'GCP', GCP_CHECKS);
  else if (id === 'iam') _spRenderIAM(c);
  else if (id === 'compliance') _spRenderCompliance(c);
  else if (id === 'terraform') _spRenderTerraform(c);
  else if (id === 'surface') _spRenderSurface(c);
  else if (id === 'attackpath') _spRenderAttackPath(c);
  else if (id === 'remediate') _spRenderRemediate(c);
  else if (id === 'trends') _spRenderTrends(c);
  else if (id === 'explorer') _spRenderExplorer(c);
}

function _spRender(main) {
  var tabs = _spBuildTabs();

  main.innerHTML =
    '<div class="sp-wrap">' +
      '<div class="sp-header">' +
        '<div class="sp-title-row">' +
          '<h1 class="sp-title">SPECTRE</h1>' +
          '<span class="sp-subtitle">Cloud Security Posture Management</span>' +
        '</div>' +
        '<div class="sp-meta">' +
          '<div id="sp-modebar"></div>' +
          '<span class="sp-meta-item">Self-assessment (no cloud connection)</span>' +
          '<span class="sp-meta-item">Checks: ' + (AWS_CHECKS.length + AZURE_CHECKS.length + GCP_CHECKS.length) + '</span>' +
          '<span class="sp-meta-item">Frameworks: ' + Object.keys(COMPLIANCE_FRAMEWORKS).length + '</span>' +
        '</div>' +
      '</div>' +
      '<div class="sp-modenote" id="sp-modenote"></div>' +
      '<div class="sp-tabs" id="sp-tabs"></div>' +
      '<div id="sp-content" style="margin-top:12px"></div>' +
    '</div>';

  var wrap = main.querySelector('.sp-wrap');
  var c = main.querySelector('#sp-content');
  var tabsEl = main.querySelector('#sp-tabs');
  var visibleTabs = tabs.slice();

  function activate(id) {
    _spActiveTab = id;
    tabsEl.querySelectorAll('.sp-tab').forEach(function (b) { b.classList.toggle('on', b.dataset.t === id); });
    _spRouteContent(id, c);
  }

  function renderTabs() {
    tabsEl.innerHTML = visibleTabs.map(function (t) {
      return '<button class="sp-tab' + (_spActiveTab === t.id ? ' on' : '') + '" data-t="' + t.id + '">' + esc(t.label) + '</button>';
    }).join('');
    tabsEl.querySelectorAll('.sp-tab').forEach(function (b) {
      b.onclick = function () { activate(b.dataset.t); };
    });
  }

  // Operational-mode switcher: filters the tab bar to the active posture and
  // re-tints the console. Persists the last-used mode per tool via core/store.
  mountModeSwitcher({
    toolId: 'spectre',
    tabs: tabs,
    mount: main.querySelector('#sp-modebar'),
    host: wrap,
    note: main.querySelector('#sp-modenote'),
    onChange: function (_mode, vt) {
      visibleTabs = vt;
      if (!visibleTabs.some(function (t) { return t.id === _spActiveTab; })) {
        _spActiveTab = visibleTabs[0] ? visibleTabs[0].id : 'dashboard';
      }
      renderTabs();
      activate(_spActiveTab);
    }
  });
}

// ============================================================================
// TAB 1 — POSTURE DASHBOARD
// ============================================================================
function _spRenderDashboard(c) {
  var allResults = _spResultsFor(AWS_CHECKS).concat(_spResultsFor(AZURE_CHECKS)).concat(_spResultsFor(GCP_CHECKS));
  var hasData = allResults.length > 0;
  var total = allResults.length;
  var passed = allResults.filter(function(r) { return r.status === 'PASS'; }).length;
  var failed = allResults.filter(function(r) { return r.status === 'FAIL'; }).length;
  var warned = allResults.filter(function(r) { return r.status === 'WARN'; }).length;
  var score = hasData ? _spPct(passed, total) : 0;
  var scoreColor = score > 70 ? '#22c55e' : score > 40 ? '#eab308' : '#dc2626';

  var sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  allResults.filter(function(r) { return r.status === 'FAIL'; }).forEach(function(r) { sevCounts[r.severity] = (sevCounts[r.severity] || 0) + 1; });

  var services = {};
  allResults.forEach(function(r) {
    if (!services[r.service]) services[r.service] = { pass: 0, fail: 0, warn: 0, total: 0 };
    services[r.service].total++;
    if (r.status === 'PASS') services[r.service].pass++;
    else if (r.status === 'FAIL') services[r.service].fail++;
    else services[r.service].warn++;
  });

  var progress = _SP_CLOUDS.map(function (pair) { return { cloud: pair[0], answered: _spAnsweredCount(pair[1]), total: pair[1].length }; });

  c.innerHTML =
    '<div class="sp-grid-3">' +
      '<div class="sp-card sp-score-card">' +
        '<div class="sp-card-h">Security Score</div>' +
        '<div class="sp-gauge-wrap">' +
          '<svg class="sp-gauge" viewBox="0 0 120 120">' +
            '<circle cx="60" cy="60" r="52" fill="none" stroke="rgba(100,116,139,.15)" stroke-width="8"/>' +
            '<circle cx="60" cy="60" r="52" fill="none" stroke="' + scoreColor + '" stroke-width="8" stroke-dasharray="' + (326.7 * (score / 100)) + ' 326.7" stroke-linecap="round" transform="rotate(-90 60 60)" style="transition:stroke-dasharray .6s ease"/>' +
            '<text x="60" y="55" text-anchor="middle" fill="' + scoreColor + '" font-size="28" font-weight="800">' + score + '</text>' +
            '<text x="60" y="72" text-anchor="middle" fill="currentColor" font-size="10" opacity=".6">/ 100</text>' +
          '</svg>' +
        '</div>' +
        (hasData ? '<div class="sp-score-detail">' + passed + ' passed / ' + failed + ' failed (from your answers)</div>' : '<div class="sp-score-detail">Answer checks in the AWS, Azure or GCP tab to see your score</div>') +
      '</div>' +
      '<div class="sp-card">' +
        '<div class="sp-card-h">Risk Breakdown</div>' +
        '<div class="sp-sev-bars">' +
          ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(function(s) {
            var cnt = sevCounts[s] || 0;
            var maxC = Math.max(sevCounts.CRITICAL, sevCounts.HIGH, sevCounts.MEDIUM, sevCounts.LOW, 1);
            return '<div class="sp-sev-row"><span class="sp-sev-label" style="color:' + _spSevColor(s) + '">' + s + '</span><div class="sp-sev-bar-bg"><div class="sp-sev-bar-fill" style="width:' + _spPct(cnt, maxC) + '%;background:' + _spSevColor(s) + '"></div></div><span class="sp-sev-cnt">' + cnt + '</span></div>';
          }).join('') +
        '</div>' +
        (!hasData ? '<div class="sp-empty">No answers yet</div>' : '') +
      '</div>' +
      '<div class="sp-card">' +
        '<div class="sp-card-h">Checklist Progress</div>' +
        '<div class="sp-comp-bars">' +
          progress.map(function(p) {
            return '<div class="sp-comp-row"><span class="sp-comp-name">' + esc(p.cloud) + '</span><div class="sp-comp-bar-bg"><div class="sp-comp-bar-fill" style="width:' + _spPct(p.answered, p.total) + '%;background:var(--acc)"></div></div><span class="sp-comp-pct">' + p.answered + '/' + p.total + '</span></div>';
          }).join('') +
        '</div>' +
      '</div>' +
    '</div>' +
    '<div class="sp-grid-2" style="margin-top:16px">' +
      '<div class="sp-card">' +
        '<div class="sp-card-h">Compliance Coverage</div>' +
        '<div class="sp-comp-bars">' +
          Object.keys(COMPLIANCE_FRAMEWORKS).map(function(key) {
            var fw = COMPLIANCE_FRAMEWORKS[key];
            var sts = fw.controls.map(function(c2) { return _spControlStatus(key, c2); });
            var pass = sts.filter(function(v) { return v === 'pass'; }).length;
            var scored = sts.filter(function(v) { return v && v !== 'na'; }).length;
            var pct = _spPct(pass, scored);
            var color = pct > 70 ? '#22c55e' : pct > 40 ? '#eab308' : '#dc2626';
            return '<div class="sp-comp-row"><span class="sp-comp-name">' + esc(fw.name) + '</span><div class="sp-comp-bar-bg"><div class="sp-comp-bar-fill" style="width:' + pct + '%;background:' + color + '"></div></div><span class="sp-comp-pct">' + (scored ? pct + '%' : '--') + '</span></div>';
          }).join('') +
        '</div>' +
      '</div>' +
      '<div class="sp-card">' +
        '<div class="sp-card-h">Service Breakdown</div>' +
        (Object.keys(services).length ? '<div class="sp-svc-list">' +
          Object.keys(services).sort().map(function(svc) {
            var d = services[svc];
            return '<div class="sp-svc-row"><span class="sp-svc-name">' + esc(svc) + '</span><span class="sp-svc-pass">' + d.pass + ' pass</span><span class="sp-svc-fail" style="color:#dc2626">' + d.fail + ' fail</span><span class="sp-svc-total">' + d.total + ' total</span></div>';
          }).join('') +
        '</div>' : '<div class="sp-empty">Answer cloud checks to see a service breakdown</div>') +
      '</div>' +
    '</div>' +
    '<div class="sp-card" style="margin-top:16px">' +
      '<div class="sp-card-h">Top Critical Misconfigurations</div>' +
      (allResults.filter(function(r) { return r.status === 'FAIL'; }).length ?
        '<table class="sp-table"><thead><tr><th>Check ID</th><th>Service</th><th>Finding</th><th>Severity</th><th>CIS</th></tr></thead><tbody>' +
        allResults.filter(function(r) { return r.status === 'FAIL'; }).sort(function(a, b) { var o = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }; return (o[a.severity] || 4) - (o[b.severity] || 4); }).slice(0, 10).map(function(r) {
          return '<tr><td class="sp-mono">' + esc(r.id) + '</td><td>' + esc(r.service) + '</td><td>' + esc(r.name) + '</td><td><span class="sp-sev-badge" style="color:' + _spSevColor(r.severity) + ';background:' + _spSevBg(r.severity) + '">' + r.severity + '</span></td><td class="sp-mono">' + esc(r.cis || '') + '</td></tr>';
        }).join('') +
        '</tbody></table>' : '<div class="sp-empty">No checks answered Fail. Answer checks in the AWS, Azure or GCP tabs.</div>') +
    '</div>';
}

// ============================================================================
// TAB 2/3/4 — CLOUD AUDIT (shared renderer)
// ============================================================================
// ============================================================================
// SECURITY GRAPH EXPORT
// ============================================================================
var _SP_GRAPH_SEV = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'info' };

function _spSendGraph(btn, build) {
  btn.disabled = true;
  import('/js/graph-bridge.js?v=20260923c').then(function(gb) {
    var tally = { created: 0, updated: 0, links: 0, findings: 0 };
    var push = function(item) {
      var r = gb.sendToGraph('SPECTRE', [item], undefined, true);
      tally.created += r.created; tally.updated += r.updated;
      return r.entities[0] || null;
    };
    // finding --affects--> asset
    var sendPair = function(finding, asset) {
      var f = push(finding), a = push(asset);
      tally.findings++;
      if (f && a && gb.linkEntities(f.id, a.id, 'affects')) tally.links++;
    };
    var simulated = build(sendPair);
    btn.textContent = 'Sent: ' + tally.created + ' new, ' + tally.updated + ' merged';
    gb.showGraphToast('Security Graph: ' + tally.findings + ' findings, ' + tally.created + ' added, ' + tally.links + ' links' + (simulated ? ' (tagged simulated)' : ''));
  }).catch(function() { btn.textContent = 'Security Graph unavailable'; btn.disabled = false; });
}

// Audit results come from the user's own checklist answers (no cloud API connection), so they are tagged self-assessed.
function _spSendAuditToGraph(btn, provider, results) {
  _spSendGraph(btn, function(sendPair) {
    var tags = ['spectre', 'cspm', provider.toLowerCase(), 'self-assessed'];
    results.filter(function(r) { return r.status === 'FAIL'; }).forEach(function(r) {
      var assetName = provider + ' ' + r.service;
      sendPair({
        type: 'FINDING', name: r.id + ': ' + r.name + ' (' + assetName + ')',
        data: { checkId: r.id, provider: provider, service: r.service, category: r.category, cis: r.cis, auditStatus: r.status, description: r.description, recommendation: r.recommendation, resource: assetName, selfAssessed: true },
        opts: { tags: tags.concat(['failed']), severity: _SP_GRAPH_SEV[r.severity] || null }
      }, {
        type: 'ASSET', name: assetName,
        data: { provider: provider, service: r.service, kind: 'cloud-service', selfAssessed: true },
        opts: { tags: tags.concat(['cloud-resource']) }
      });
    });
    return false;
  });
}

// Terraform findings come from a real static scan of the pasted HCL; the bundled sample config is tagged simulated.
function _spSendTfToGraph(btn, hcl, findings) {
  var simulated = hcl === TF_SAMPLE;
  var lines = hcl.split('\n');
  _spSendGraph(btn, function(sendPair) {
    var tags = ['spectre', 'terraform', 'iac'].concat(simulated ? ['simulated'] : []);
    findings.forEach(function(f) {
      // Walk up to the enclosing resource block to name the affected resource.
      var resName = f.resource;
      for (var i = f.line - 1; i >= 0; i--) {
        var m = /^\s*resource\s+"([^"]+)"\s+"([^"]+)"/.exec(lines[i]);
        if (m) { resName = m[1] + '.' + m[2]; break; }
      }
      sendPair({
        type: 'FINDING', name: f.issue + ' (' + resName + ')',
        data: { line: f.line, code: f.lineText, fix: f.fix, resource: resName, simulated: simulated },
        opts: { tags: tags, severity: _SP_GRAPH_SEV[f.severity] || null }
      }, {
        type: 'ASSET', name: resName,
        data: { resourceType: f.resource, kind: 'terraform-resource', simulated: simulated },
        opts: { tags: tags.concat(['cloud-resource']) }
      });
    });
    return simulated;
  });
}

var _SP_ANS_OPTS = [['', 'Unanswered'], ['PASS', 'Pass - not present'], ['FAIL', 'Fail - present'], ['NA', 'N/A']];
function _spRenderAudit(c, provider, checks) {
  var services = {};
  checks.forEach(function(ch) { if (!services[ch.service]) services[ch.service] = 0; services[ch.service]++; });

  var rows = checks.map(_spCheckRow);
  var results = rows.filter(function(r) { return r.status === 'PASS' || r.status === 'FAIL'; });
  var filtered = rows;
  if (_spAuditFilter.service) filtered = filtered.filter(function(r) { return r.service === _spAuditFilter.service; });
  if (_spAuditFilter.severity) filtered = filtered.filter(function(r) { return r.severity === _spAuditFilter.severity; });
  if (_spAuditFilter.status) filtered = filtered.filter(function(r) { return r.status === _spAuditFilter.status; });

  var passed = results.filter(function(r) { return r.status === 'PASS'; }).length;
  var failed = results.filter(function(r) { return r.status === 'FAIL'; }).length;
  var na = rows.filter(function(r) { return r.status === 'N/A'; }).length;
  var unanswered = rows.length - results.length - na;

  c.innerHTML =
    '<div class="sp-audit-header">' +
      '<div class="sp-audit-info">' +
        '<h2 class="sp-h2">' + esc(provider) + ' Security Checklist</h2>' +
        '<span class="sp-check-cnt">' + checks.length + ' checks across ' + Object.keys(services).length + ' services</span>' +
      '</div>' +
      '<div class="sp-audit-actions">' +
        (failed ? '<button class="sp-btn sp-btn-ghost" id="sp-audit-graph" title="Findings are tagged self-assessed">Send ' + failed + ' findings to Security Graph</button>' : '') +
        '<button class="sp-btn sp-btn-ghost" id="sp-clear-answers"' + (rows.length === unanswered ? ' disabled' : '') + '>Clear ' + esc(provider) + ' answers</button>' +
      '</div>' +
    '</div>' +
    '<p class="sp-sub">Self-assessment: Spectre does not connect to your ' + esc(provider) + ' account. Each check names a misconfiguration; review your environment and answer <b>Pass</b> if it is not present, <b>Fail</b> if it is, or <b>N/A</b> if it does not apply. Score = Pass / (Pass + Fail). Answers are saved in this browser only.</p>' +
    '<div class="sp-audit-summary">' +
      '<div class="sp-sum-item sp-sum-pass"><span class="sp-sum-n">' + passed + '</span><span class="sp-sum-l">Passed</span></div>' +
      '<div class="sp-sum-item sp-sum-fail"><span class="sp-sum-n">' + failed + '</span><span class="sp-sum-l">Failed</span></div>' +
      '<div class="sp-sum-item"><span class="sp-sum-n">' + na + '</span><span class="sp-sum-l">N/A</span></div>' +
      '<div class="sp-sum-item sp-sum-warn"><span class="sp-sum-n">' + unanswered + '</span><span class="sp-sum-l">Unanswered</span></div>' +
      '<div class="sp-sum-item"><span class="sp-sum-n">' + (results.length ? _spPct(passed, results.length) + '%' : '--') + '</span><span class="sp-sum-l">Score</span></div>' +
    '</div>' +
    '<div class="sp-service-chips">' +
      '<button class="sp-chip' + (!_spAuditFilter.service ? ' on' : '') + '" data-svc="">All</button>' +
      Object.keys(services).map(function(s) {
        return '<button class="sp-chip' + (_spAuditFilter.service === s ? ' on' : '') + '" data-svc="' + esc(s) + '">' + esc(s) + ' (' + services[s] + ')</button>';
      }).join('') +
    '</div>' +
    '<div class="sp-filter-row">' +
      '<select class="sp-select" id="sp-sev-filter"><option value="">All Severities</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select>' +
      '<select class="sp-select" id="sp-status-filter"><option value="">All Answers</option><option value="PASS">Pass</option><option value="FAIL">Fail</option><option value="N/A">N/A</option><option value="UNANSWERED">Unanswered</option></select>' +
    '</div>' +
    (filtered.length ?
      '<table class="sp-table"><thead><tr><th>ID</th><th>Service</th><th>Check</th><th>Severity</th><th>CIS</th><th>Your answer</th></tr></thead><tbody>' +
      filtered.map(function(r) {
        var cur = _spGetAnswer(r.id);
        return '<tr><td class="sp-mono">' + esc(r.id) + '</td><td>' + esc(r.service) + '</td><td title="' + esc(r.description) + '">' + esc(r.name) + '<div class="sp-cell-sub">' + esc(r.description) + '</div></td><td><span class="sp-sev-badge" style="color:' + _spSevColor(r.severity) + ';background:' + _spSevBg(r.severity) + '">' + r.severity + '</span></td><td class="sp-mono">' + esc(r.cis || '') + '</td>' +
          '<td><select class="sp-select sp-ans" data-id="' + esc(r.id) + '" aria-label="Answer for ' + esc(r.id) + '" style="color:' + _spStatusColor(r.status) + '">' +
            _SP_ANS_OPTS.map(function(o) { return '<option value="' + o[0] + '"' + (cur === o[0] ? ' selected' : '') + '>' + o[1] + '</option>'; }).join('') +
          '</select></td></tr>';
      }).join('') +
      '</tbody></table>' :
      '<div class="sp-empty">No checks match filters</div>') +
    (failed ? '<div class="sp-expand-section" style="margin-top:16px"><details><summary class="sp-details-sum">Recommendations for checks answered Fail</summary><div class="sp-rec-list">' +
      results.filter(function(r) { return r.status === 'FAIL'; }).map(function(r) {
        return '<div class="sp-rec-item"><div class="sp-rec-head"><span class="sp-sev-badge" style="color:' + _spSevColor(r.severity) + ';background:' + _spSevBg(r.severity) + '">' + r.severity + '</span><strong>' + esc(r.id) + '</strong> ' + esc(r.name) + '</div><div class="sp-rec-desc">' + esc(r.description) + '</div><div class="sp-rec-fix">Recommendation: ' + esc(r.recommendation) + '</div></div>';
      }).join('') +
    '</div></details></div>' : '');

  var rerender = function() { _spRenderAudit(c, provider, checks); };
  c.querySelectorAll('.sp-ans').forEach(function(sel) {
    sel.onchange = function() { _spSetAnswer(sel.dataset.id, sel.value); rerender(); };
  });
  var clearBtn = c.querySelector('#sp-clear-answers');
  if (clearBtn) clearBtn.onclick = function() {
    if (!confirm('Clear all ' + provider + ' checklist answers?')) return;
    var ids = {};
    checks.forEach(function(ch) { ids[ch.id] = 1; });
    _spClearAnswers(function(k) { return !!ids[k]; });
    rerender();
  };

  var auditGraphBtn = c.querySelector('#sp-audit-graph');
  if (auditGraphBtn) auditGraphBtn.onclick = function() { _spSendAuditToGraph(auditGraphBtn, provider, results); };

  c.querySelectorAll('.sp-chip').forEach(function(chip) {
    chip.onclick = function() { _spAuditFilter.service = chip.dataset.svc; rerender(); };
  });
  var sevFilter = c.querySelector('#sp-sev-filter');
  if (sevFilter) { sevFilter.value = _spAuditFilter.severity; sevFilter.onchange = function() { _spAuditFilter.severity = sevFilter.value; rerender(); }; }
  var statusFilter = c.querySelector('#sp-status-filter');
  if (statusFilter) { statusFilter.value = _spAuditFilter.status; statusFilter.onchange = function() { _spAuditFilter.status = statusFilter.value; rerender(); }; }
}

// ============================================================================
// TAB 5 — IAM ANALYZER
// ============================================================================
function _spRenderIAM(c) {
  c.innerHTML =
    '<h2 class="sp-h2">IAM Policy Analyzer</h2>' +
    '<p class="sp-sub">Paste an AWS IAM policy JSON or load a sample to analyze permissions, detect overprivilege, and get recommendations.</p>' +
    '<div class="sp-iam-controls">' +
      '<div class="sp-iam-samples">' +
        Object.keys(IAM_SAMPLES).map(function(key) {
          return '<button class="sp-btn sp-btn-ghost sp-btn-sm' + (_spSelectedPolicy === key ? ' sp-btn-active' : '') + '" data-pol="' + key + '">' + esc(IAM_SAMPLES[key].name) + '</button>';
        }).join('') +
      '</div>' +
      '<button class="sp-btn sp-btn-primary" id="sp-analyze-iam">Analyze Policy</button>' +
    '</div>' +
    '<textarea class="sp-textarea" id="sp-iam-input" placeholder="Paste IAM policy JSON here..." rows="10">' + (_spSelectedPolicy ? JSON.stringify(IAM_SAMPLES[_spSelectedPolicy].policy, null, 2) : '') + '</textarea>' +
    (_spIamFindings ? '<div class="sp-iam-results">' +
      '<h3 class="sp-h3">Risk Analysis — ' + _spIamFindings.length + ' finding' + (_spIamFindings.length !== 1 ? 's' : '') + '</h3>' +
      (_spIamFindings.length ? '<table class="sp-table"><thead><tr><th>Severity</th><th>Finding</th><th>Statement</th><th>Recommendation</th></tr></thead><tbody>' +
        _spIamFindings.map(function(f) {
          return '<tr><td><span class="sp-sev-badge" style="color:' + _spSevColor(f.severity) + ';background:' + _spSevBg(f.severity) + '">' + f.severity + '</span></td><td>' + esc(f.finding) + '</td><td>#' + f.statement + '</td><td>' + esc(f.recommendation) + '</td></tr>';
        }).join('') +
      '</tbody></table>' : '<div class="sp-ok-msg">No issues found. Policy follows least privilege.</div>') +
    '</div>' : '') +
    (_spIamMatrix ? '<div class="sp-iam-matrix">' +
      '<h3 class="sp-h3">Permission Matrix</h3>' +
      '<div class="sp-matrix-grid">' +
        Object.keys(_spIamMatrix).sort().map(function(svc) {
          var level = _spIamMatrix[svc];
          var color = level === 'Admin' ? '#dc2626' : level === 'Write' ? '#f97316' : '#22c55e';
          var bg = level === 'Admin' ? 'rgba(220,38,38,.1)' : level === 'Write' ? 'rgba(249,115,22,.1)' : 'rgba(34,197,94,.1)';
          return '<div class="sp-matrix-cell" style="border-color:' + color + ';background:' + bg + '"><div class="sp-matrix-svc">' + esc(svc) + '</div><div class="sp-matrix-lvl" style="color:' + color + '">' + level + '</div></div>';
        }).join('') +
      '</div>' +
    '</div>' : '') +
    '<div class="sp-iam-legend" style="margin-top:12px">' +
      '<span class="sp-legend-item"><span class="sp-legend-dot" style="background:#dc2626"></span>Admin (full access)</span>' +
      '<span class="sp-legend-item"><span class="sp-legend-dot" style="background:#f97316"></span>Write (modify resources)</span>' +
      '<span class="sp-legend-item"><span class="sp-legend-dot" style="background:#22c55e"></span>Read (view only)</span>' +
    '</div>';

  c.querySelectorAll('[data-pol]').forEach(function(btn) {
    btn.onclick = function() {
      _spSelectedPolicy = btn.dataset.pol;
      _spIamFindings = null; _spIamMatrix = null;
      _spRender(c.closest('.sp-wrap').parentNode);
    };
  });

  c.querySelector('#sp-analyze-iam').onclick = function() {
    var input = c.querySelector('#sp-iam-input').value.trim();
    try {
      var policy = JSON.parse(input);
      _spIamFindings = _spAnalyzeIAM(policy);
      _spIamMatrix = _spBuildPermMatrix(policy);
      _spRender(c.closest('.sp-wrap').parentNode);
    } catch (e) {
      alert('Invalid JSON. Please paste a valid IAM policy document.');
    }
  };
}

// ============================================================================
// TAB 6 — COMPLIANCE
// ============================================================================
function _spRenderCompliance(c) {
  var fwKey = _spComplianceTab;
  var fw = COMPLIANCE_FRAMEWORKS[fwKey];
  var st = function(ct) { return _spControlStatus(fwKey, ct); };
  var passed = fw.controls.filter(function(ct) { return st(ct) === 'pass'; }).length;
  var failed = fw.controls.filter(function(ct) { return st(ct) === 'fail'; }).length;
  var partial = fw.controls.filter(function(ct) { return st(ct) === 'partial'; }).length;
  var naCount = fw.controls.filter(function(ct) { return st(ct) === 'na'; }).length;
  var unanswered = fw.controls.length - passed - failed - partial - naCount;
  var scored = passed + failed + partial;
  var pct = _spPct(passed, scored);
  var pctColor = pct > 70 ? '#22c55e' : pct > 40 ? '#eab308' : '#dc2626';

  c.innerHTML =
    '<h2 class="sp-h2">Compliance Self-Assessment</h2>' +
    '<p class="sp-sub">Mark each control for your organisation. Nothing is checked automatically; the percentage is Implemented / (Implemented + Partial + Not Implemented), N/A excluded. Answers are saved in this browser only.</p>' +
    '<div class="sp-comp-tabs">' +
      Object.keys(COMPLIANCE_FRAMEWORKS).map(function(key) {
        return '<button class="sp-comp-tab' + (_spComplianceTab === key ? ' on' : '') + '" data-fw="' + key + '">' + esc(COMPLIANCE_FRAMEWORKS[key].name) + '</button>';
      }).join('') +
    '</div>' +
    '<div class="sp-comp-summary">' +
      '<div class="sp-comp-score" style="border-color:' + pctColor + '"><span class="sp-comp-pct-big" style="color:' + pctColor + '">' + (scored ? pct + '%' : '--') + '</span><span class="sp-comp-pct-label">Compliant</span></div>' +
      '<div class="sp-comp-stats">' +
        '<div class="sp-comp-stat"><span class="sp-comp-stat-n" style="color:#22c55e">' + passed + '</span><span>Implemented</span></div>' +
        '<div class="sp-comp-stat"><span class="sp-comp-stat-n" style="color:#eab308">' + partial + '</span><span>Partial</span></div>' +
        '<div class="sp-comp-stat"><span class="sp-comp-stat-n" style="color:#dc2626">' + failed + '</span><span>Not Implemented</span></div>' +
        '<div class="sp-comp-stat"><span class="sp-comp-stat-n">' + unanswered + '</span><span>Unanswered</span></div>' +
        '<div class="sp-comp-stat"><span class="sp-comp-stat-n">' + fw.controls.length + '</span><span>Total Controls</span></div>' +
      '</div>' +
    '</div>' +
    '<table class="sp-table"><thead><tr><th>Control ID</th><th>Control Name</th><th>Category</th><th>Status</th></tr></thead><tbody>' +
      fw.controls.map(function(ct) {
        var cur = st(ct);
        return '<tr><td class="sp-mono">' + esc(ct.id) + '</td><td>' + esc(ct.name) + '</td><td>' + esc(ct.category) + '</td><td>' +
          '<select class="sp-select sp-cmp-ans" data-id="' + esc(ct.id) + '" aria-label="Status for ' + esc(ct.id) + '">' +
            [['', 'Unanswered'], ['pass', 'Implemented'], ['partial', 'Partial'], ['fail', 'Not implemented'], ['na', 'N/A']].map(function(o) {
              return '<option value="' + o[0] + '"' + (cur === o[0] ? ' selected' : '') + '>' + o[1] + '</option>';
            }).join('') +
          '</select></td></tr>';
      }).join('') +
    '</tbody></table>' +
    '<div class="sp-comp-actions" style="margin-top:16px">' +
      '<button class="sp-btn sp-btn-ghost" id="sp-export-compliance">Export Compliance Report</button>' +
    '</div>' +
    (failed > 0 ? '<div class="sp-gap-analysis" style="margin-top:16px"><h3 class="sp-h3">Gap Analysis — ' + failed + ' controls need attention</h3>' +
      fw.controls.filter(function(ct) { return st(ct) === 'fail'; }).map(function(ct) {
        return '<div class="sp-gap-item"><span class="sp-status sp-fail">NOT IMPLEMENTED</span> <strong>' + esc(ct.id) + '</strong> — ' + esc(ct.name) + ' <span class="sp-gap-cat">(' + esc(ct.category) + ')</span></div>';
      }).join('') +
    '</div>' : '');

  c.querySelectorAll('.sp-cmp-ans').forEach(function(sel) {
    sel.onchange = function() { _spSetAnswer('cmp:' + fwKey + ':' + sel.dataset.id, sel.value); _spRenderCompliance(c); };
  });
  c.querySelectorAll('.sp-comp-tab').forEach(function(btn) {
    btn.onclick = function() { _spComplianceTab = btn.dataset.fw; _spRender(c.closest('.sp-wrap').parentNode); };
  });

  var exportBtn = c.querySelector('#sp-export-compliance');
  if (exportBtn) {
    exportBtn.onclick = function() {
      var report = '# ' + fw.name + ' Compliance Self-Assessment\n\nDate: ' + new Date().toISOString().split('T')[0] + '\nBasis: self-reported answers (not an automated audit)\nScore: ' + (scored ? pct + '%' : 'n/a') + '\n\n';
      fw.controls.forEach(function(ct) { report += ct.id + ' | ' + ct.name + ' | ' + ((st(ct) || 'unanswered').toUpperCase()) + '\n'; });
      var blob = new Blob([report], { type: 'text/plain' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url; a.download = _spComplianceTab + '-compliance-report.txt'; a.click();
      URL.revokeObjectURL(url);
    };
  }
}

// ============================================================================
// TAB 7 — TERRAFORM SCANNER
// ============================================================================
function _spRenderTerraform(c) {
  c.innerHTML =
    '<h2 class="sp-h2">Terraform Security Scanner</h2>' +
    '<p class="sp-sub">Paste Terraform HCL configuration to detect security issues before deployment.</p>' +
    '<div class="sp-tf-controls">' +
      '<button class="sp-btn sp-btn-primary" id="sp-scan-tf">Scan Configuration</button>' +
      '<button class="sp-btn sp-btn-ghost" id="sp-load-tf-demo">Load Sample Config</button>' +
      (_spTfFindings && _spTfFindings.length ? '<button class="sp-btn sp-btn-ghost" id="sp-tf-graph">Send ' + _spTfFindings.length + ' findings to Security Graph</button>' : '') +
      '<span class="sp-tf-checks">' + TF_CHECKS.length + ' security checks</span>' +
    '</div>' +
    '<div class="sp-tf-layout">' +
      '<div class="sp-tf-editor">' +
        '<div class="sp-tf-label">Terraform Configuration</div>' +
        '<textarea class="sp-textarea sp-tf-input" id="sp-tf-input" rows="24" placeholder="Paste your Terraform HCL here...">' + esc(c._tfValue || _spTfSource || '') + '</textarea>' +
      '</div>' +
      (_spTfFindings ? '<div class="sp-tf-results">' +
        '<div class="sp-tf-label">Scan Results — ' + _spTfFindings.length + ' issue' + (_spTfFindings.length !== 1 ? 's' : '') + ' found</div>' +
        (_spTfFindings.length ?
          '<div class="sp-tf-summary">' +
            '<span class="sp-tf-stat"><span style="color:#dc2626;font-weight:700">' + _spTfFindings.filter(function(f) { return f.severity === 'CRITICAL'; }).length + '</span> Critical</span>' +
            '<span class="sp-tf-stat"><span style="color:#f97316;font-weight:700">' + _spTfFindings.filter(function(f) { return f.severity === 'HIGH'; }).length + '</span> High</span>' +
            '<span class="sp-tf-stat"><span style="color:#eab308;font-weight:700">' + _spTfFindings.filter(function(f) { return f.severity === 'MEDIUM'; }).length + '</span> Medium</span>' +
          '</div>' +
          '<div class="sp-tf-findings">' +
            _spTfFindings.map(function(f) {
              return '<div class="sp-tf-finding"><div class="sp-tf-finding-head"><span class="sp-sev-badge" style="color:' + _spSevColor(f.severity) + ';background:' + _spSevBg(f.severity) + '">' + f.severity + '</span><span class="sp-tf-finding-line">Line ' + f.line + '</span></div><div class="sp-tf-finding-issue">' + esc(f.issue) + '</div><div class="sp-tf-finding-code">' + esc(f.lineText) + '</div><div class="sp-tf-finding-fix">Fix: ' + esc(f.fix) + '</div></div>';
            }).join('') +
          '</div>' :
          '<div class="sp-ok-msg">No security issues detected. Configuration looks good.</div>') +
      '</div>' : '<div class="sp-tf-results"><div class="sp-tf-label">Scan Results</div><div class="sp-empty">Paste or load a Terraform config and click "Scan Configuration"</div></div>') +
    '</div>';

  c.querySelector('#sp-load-tf-demo').onclick = function() {
    c.querySelector('#sp-tf-input').value = TF_SAMPLE;
    c._tfValue = TF_SAMPLE;
  };

  var tfGraphBtn = c.querySelector('#sp-tf-graph');
  if (tfGraphBtn) tfGraphBtn.onclick = function() { _spSendTfToGraph(tfGraphBtn, _spTfSource, _spTfFindings); };

  c.querySelector('#sp-scan-tf').onclick = function() {
    var hcl = c.querySelector('#sp-tf-input').value;
    c._tfValue = hcl;
    if (!hcl.trim()) { alert('Please paste a Terraform configuration first.'); return; }
    _spTfFindings = _spRunTfScan(hcl);
    _spTfSource = hcl;
    _spRender(c.closest('.sp-wrap').parentNode);
  };
}

// ============================================================================
// TAB 8 — ATTACK SURFACE
// ============================================================================
function _spRenderSurface(c) {
  var snap = _spBuildSnapshot();
  var exposed = [];
  snap.forEach(function (r) { if (r.status !== 'FAIL') return; var ex = _spClassifyExposure(r); if (ex) exposed.push({ r: r, type: ex.type, why: ex.why }); });
  exposed.sort(function (a, b) {
    var s = _SP_SEV_ORDER[a.r.severity] - _SP_SEV_ORDER[b.r.severity]; if (s) return s;
    var cl = _SP_CLOUD_ORDER[a.r.cloud] - _SP_CLOUD_ORDER[b.r.cloud]; if (cl) return cl;
    return a.r.id < b.r.id ? -1 : 1;
  });
  var byCloud = { AWS: 0, Azure: 0, GCP: 0 };
  var crit = 0;
  var typeCounts = {};
  exposed.forEach(function (e) {
    byCloud[e.r.cloud]++;
    if (e.r.severity === 'CRITICAL') crit++;
    typeCounts[e.type] = (typeCounts[e.type] || 0) + 1;
  });

  c.innerHTML =
    '<h2 class="sp-h2">Internet Attack Surface</h2>' +
    '<p class="sp-sub">Every check you answered Fail that leaves a resource reachable from the public internet, aggregated across AWS, Azure and GCP and ranked by severity. This is the "what can an attacker reach from outside" view.</p>' +
    _spAnswerNote(snap) +
    '<div class="sp-stat-tiles">' +
      _spStatTile(exposed.length, 'Exposed Findings', 'var(--acc)') +
      _spStatTile(crit, 'Critical Exposures', '#dc2626') +
      _spStatTile(byCloud.AWS, 'AWS', '#f97316') +
      _spStatTile(byCloud.Azure, 'Azure', '#3b82f6') +
      _spStatTile(byCloud.GCP, 'GCP', '#22c55e') +
    '</div>' +
    '<div class="sp-chip-legend">' +
      Object.keys(typeCounts).sort().map(function (k) { return '<span class="sp-legend-chip">' + esc(k) + ' <b>' + typeCounts[k] + '</b></span>'; }).join('') +
    '</div>' +
    (exposed.length ?
      '<table class="sp-table"><thead><tr><th>Check</th><th>Cloud</th><th>Exposure Type</th><th>Severity</th><th>Why It Matters</th></tr></thead><tbody>' +
      exposed.map(function (e) {
        return '<tr><td class="sp-mono">' + esc(e.r.id) + '<div class="sp-cell-sub">' + esc(e.r.service) + ' · ' + esc(e.r.name) + '</div></td>' +
          '<td>' + esc(e.r.cloud) + '</td>' +
          '<td>' + esc(e.type) + '</td>' +
          '<td><span class="sp-sev-badge" style="color:' + _spSevColor(e.r.severity) + ';background:' + _spSevBg(e.r.severity) + '">' + e.r.severity + '</span></td>' +
          '<td class="sp-why">' + esc(e.why) + '</td></tr>';
      }).join('') +
      '</tbody></table>' :
      '<div class="sp-empty">No internet-exposure checks answered Fail.</div>');
}

// ============================================================================
// TAB 9 — REMEDIATION PLAN
// ============================================================================
function _spRenderRemediate(c) {
  var snap = _spBuildSnapshot();
  var failing = snap.filter(function (r) { return r.status === 'FAIL'; });
  failing.forEach(function (r) { r.effort = _spEffort(r); });
  var effRank = { Low: 0, Medium: 1, High: 2 };
  var queue = failing.filter(function (r) { return !_spRemedEffort || r.effort === _spRemedEffort; });
  queue.sort(function (a, b) {
    var s = _SP_SEV_ORDER[a.severity] - _SP_SEV_ORDER[b.severity]; if (s) return s;
    var e = effRank[a.effort] - effRank[b.effort]; if (e) return e;
    var cl = _SP_CLOUD_ORDER[a.cloud] - _SP_CLOUD_ORDER[b.cloud]; if (cl) return cl;
    return a.id < b.id ? -1 : 1;
  });
  var sev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  var eff = { Low: 0, Medium: 0, High: 0 };
  failing.forEach(function (r) { sev[r.severity]++; eff[r.effort]++; });
  var snippets = queue.map(_spRemediationSnippet);

  c.innerHTML =
    '<h2 class="sp-h2">Remediation Plan</h2>' +
    '<p class="sp-sub">A prioritised fix queue built from every check you answered Fail across the three clouds, sorted by severity then estimated effort then cloud. Each item carries a copyable remediation command template; replace the &lt;your-...&gt; placeholder with your resource name.</p>' +
    _spAnswerNote(snap) +
    '<div class="sp-stat-tiles">' +
      _spStatTile(failing.length, 'Open Findings', 'var(--acc)') +
      _spStatTile(sev.CRITICAL, 'Critical', '#dc2626') +
      _spStatTile(sev.HIGH, 'High', '#f97316') +
      _spStatTile(sev.MEDIUM, 'Medium', '#eab308') +
      _spStatTile(eff.Low + ' / ' + eff.Medium + ' / ' + eff.High, 'Effort L / M / H', 'var(--txt)') +
    '</div>' +
    '<div class="sp-service-chips">' +
      ['', 'Low', 'Medium', 'High'].map(function (e) {
        return '<button class="sp-chip' + (_spRemedEffort === e ? ' on' : '') + '" data-eff="' + e + '">' + (e ? esc(e) + ' effort (' + eff[e] + ')' : 'All effort') + '</button>';
      }).join('') +
    '</div>' +
    '<div class="sp-remed-list">' +
      queue.map(function (r, i) {
        var sn = snippets[i];
        return '<div class="sp-remed-item">' +
          '<div class="sp-remed-head">' +
            '<span class="sp-sev-badge" style="color:' + _spSevColor(r.severity) + ';background:' + _spSevBg(r.severity) + '">' + r.severity + '</span>' +
            '<span class="sp-remed-cloud">' + esc(r.cloud) + '</span>' +
            '<strong class="sp-remed-title">' + esc(r.id) + ' — ' + esc(r.name) + '</strong>' +
            '<span class="sp-effort sp-effort-' + r.effort.toLowerCase() + '">' + r.effort + ' effort</span>' +
          '</div>' +
          '<div class="sp-remed-desc">' + esc(r.description) + '</div>' +
          '<div class="sp-remed-fix">Fix: ' + esc(r.recommendation) + '</div>' +
          '<div class="sp-code-block"><div class="sp-code-bar"><span class="sp-code-lang">' + esc(sn.lang) + '</span><button class="sp-copy-btn" data-idx="' + i + '" data-label="Copy">Copy</button></div><pre class="sp-code">' + esc(sn.code) + '</pre></div>' +
        '</div>';
      }).join('') +
      (queue.length ? '' : '<div class="sp-empty">' + (failing.length ? 'No findings match this effort filter.' : 'No checks answered Fail yet.') + '</div>') +
    '</div>';

  c.querySelectorAll('.sp-chip').forEach(function (chip) {
    chip.onclick = function () { _spRemedEffort = chip.dataset.eff; _spRender(c.closest('.sp-wrap').parentNode); };
  });
  c.querySelectorAll('.sp-copy-btn').forEach(function (btn) {
    btn.onclick = function () { _spCopyText(snippets[+btn.dataset.idx].code, btn); };
  });
}

// ============================================================================
// TAB 10 — RISK TRENDS (your own recorded history)
// ============================================================================
// One point per day is recorded locally whenever checklist answers change
// (see _spRecordHistory). Nothing is invented: with fewer than two recorded
// days there is no trend line to show.
function _spRenderTrends(c) {
  var snap = _spBuildSnapshot();
  var scoredAll = snap.filter(function (r) { return r.status === 'PASS' || r.status === 'FAIL'; });
  var passAll = scoredAll.filter(function (r) { return r.status === 'PASS'; }).length;
  var overall = scoredAll.length ? _spPct(passAll, scoredAll.length) : null;
  var history = _spLoadHistory();

  var clouds = _SP_CLOUDS.map(function (pair) {
    var rows = snap.filter(function (r) { return r.cloud === pair[0] && (r.status === 'PASS' || r.status === 'FAIL'); });
    var pass = rows.filter(function (r) { return r.status === 'PASS'; }).length;
    var hist = history.map(function (h) { return h.p[pair[0]]; }).filter(function (v) { return typeof v === 'number'; });
    return { cloud: pair[0], score: rows.length ? _spPct(pass, rows.length) : null, hist: hist };
  });
  var overallHist = history.map(function (h) { return h.p.overall; }).filter(function (v) { return typeof v === 'number'; });

  var barColor = function (v) { return v == null ? '#64748b' : v > 70 ? '#22c55e' : v > 40 ? '#eab308' : '#dc2626'; };
  var deltaStr = function (d) { return (d >= 0 ? '+' : '') + d; };
  var deltaColor = function (d) { return d >= 0 ? '#22c55e' : '#dc2626'; };
  var trendBlock = function (hist, w, h, color) {
    if (hist.length < 2) return '<div class="sp-empty" style="padding:12px">Not enough history yet. A point is recorded each day you update answers.</div>';
    return _spSparkline(hist, w, h, color);
  };
  var deltaHtml = function (hist, suffix) {
    if (hist.length < 2) return '';
    var d = hist[hist.length - 1] - hist[0];
    return '<span class="sp-trend-delta" style="color:' + deltaColor(d) + '">' + deltaStr(d) + (suffix || '') + '</span>';
  };

  c.innerHTML =
    '<h2 class="sp-h2">Risk Trends</h2>' +
    '<p class="sp-sub">Your checklist score over time, recorded in this browser (one point per day, whenever you change answers). There is no live cloud telemetry.</p>' +
    _spAnswerNote(snap) +
    '<div class="sp-card">' +
      '<div class="sp-card-h">Overall Checklist Score' + (history.length ? ' - ' + history.length + ' recorded day' + (history.length === 1 ? '' : 's') : '') + '</div>' +
      '<div class="sp-trend-top"><span class="sp-trend-now" style="color:' + barColor(overall) + '">' + (overall == null ? '--' : overall) + '</span><span class="sp-trend-unit">/ 100</span>' + deltaHtml(overallHist, ' since ' + (history[0] ? esc(history[0].date) : '')) + '</div>' +
      trendBlock(overallHist, 600, 90, barColor(overall)) +
      (overallHist.length >= 2 ? '<div class="sp-trend-axis"><span>' + esc(history[0].date) + ': ' + overallHist[0] + '%</span><span>Latest: ' + overallHist[overallHist.length - 1] + '%</span></div>' : '') +
    '</div>' +
    '<div class="sp-grid-3" style="margin-top:14px">' +
      clouds.map(function (cd) {
        return '<div class="sp-card">' +
          '<div class="sp-card-h">' + esc(cd.cloud) + ' score</div>' +
          '<div class="sp-trend-top"><span class="sp-trend-now" style="color:' + barColor(cd.score) + '">' + (cd.score == null ? '--' : cd.score) + '</span><span class="sp-trend-unit">/ 100</span>' + deltaHtml(cd.hist) + '</div>' +
          trendBlock(cd.hist, 300, 60, barColor(cd.score)) +
        '</div>';
      }).join('') +
    '</div>';
}

// ============================================================================
// TAB 11 — FINDINGS EXPLORER
// ============================================================================
function _spRenderExplorer(c) {
  var snap = _spBuildSnapshot();
  var total = snap.length;
  var f = _spExplorer;

  c.innerHTML =
    '<h2 class="sp-h2">Findings Explorer</h2>' +
    '<p class="sp-sub">Every check across AWS, Azure and GCP in one dense, filterable table, with the answer you gave for each. Narrow by cloud, severity or answer, or search titles and IDs. Filters apply live.</p>' +
    _spAnswerNote(snap) +
    '<div class="sp-exp-filters">' +
      '<input class="sp-search" id="sp-exp-q" type="text" placeholder="Search title, id or service..." value="' + esc(f.q) + '">' +
      '<select class="sp-select" id="sp-exp-cloud"><option value="">All Clouds</option><option value="AWS">AWS</option><option value="Azure">Azure</option><option value="GCP">GCP</option></select>' +
      '<select class="sp-select" id="sp-exp-sev"><option value="">All Severities</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select>' +
      '<select class="sp-select" id="sp-exp-status"><option value="">All Answers</option><option value="PASS">Pass</option><option value="FAIL">Fail</option><option value="N/A">N/A</option><option value="UNANSWERED">Unanswered</option></select>' +
      '<span class="sp-exp-count" id="sp-exp-count"></span>' +
    '</div>' +
    '<table class="sp-table"><thead><tr><th>ID</th><th>Cloud</th><th>Service</th><th>Check</th><th>Category</th><th>Answer</th><th>Severity</th><th>CIS</th></tr></thead><tbody id="sp-exp-body"></tbody></table>';

  var cloudSel = c.querySelector('#sp-exp-cloud'); cloudSel.value = f.cloud;
  var sevSel = c.querySelector('#sp-exp-sev'); sevSel.value = f.severity;
  var statusSel = c.querySelector('#sp-exp-status'); statusSel.value = f.status;
  var qInput = c.querySelector('#sp-exp-q');
  var body = c.querySelector('#sp-exp-body');
  var countEl = c.querySelector('#sp-exp-count');

  function apply() {
    _spExplorer = { cloud: cloudSel.value, severity: sevSel.value, status: statusSel.value, q: qInput.value };
    var q = qInput.value.trim().toLowerCase();
    var rows = snap.filter(function (r) {
      if (cloudSel.value && r.cloud !== cloudSel.value) return false;
      if (sevSel.value && r.severity !== sevSel.value) return false;
      if (statusSel.value && r.status !== statusSel.value) return false;
      if (q && (r.name + ' ' + r.service + ' ' + r.id).toLowerCase().indexOf(q) < 0) return false;
      return true;
    });
    countEl.textContent = 'Showing ' + rows.length + ' of ' + total;
    body.innerHTML = rows.length ? rows.map(function (r) {
      return '<tr><td class="sp-mono">' + esc(r.id) + '</td><td>' + esc(r.cloud) + '</td><td>' + esc(r.service) + '</td><td title="' + esc(r.description) + '">' + esc(r.name) + '</td><td>' + esc(r.category) + '</td><td><span class="sp-status-badge" style="color:' + _spStatusColor(r.status) + '">' + r.status + '</span></td><td><span class="sp-sev-badge" style="color:' + _spSevColor(r.severity) + ';background:' + _spSevBg(r.severity) + '">' + r.severity + '</span></td><td class="sp-mono">' + esc(r.cis || '') + '</td></tr>';
    }).join('') : '<tr><td colspan="8"><div class="sp-empty">No checks match the current filters.</div></td></tr>';
  }
  cloudSel.onchange = apply; sevSel.onchange = apply; statusSel.onchange = apply;
  qInput.oninput = apply;
  apply();
}

// ============================================================================
// SCOUTING TAB — EXTERNAL ATTACK-SURFACE RECON (outside-in enumeration)
// ============================================================================
// Reconnaissance view: enumerate everything an attacker can see or reach from
// outside the accounts, derived entirely from the deterministic posture
// snapshot. Publicly-reachable resources are grouped the way an adversary maps
// them ("what does the perimeter look like?"), plus the over-permissive
// identity surface that turns a foothold into full compromise. A weighted
// exposure score summarises how wide open the estate is.
var _SP_RECON_GROUPS = [
  { key: 'data', label: 'Exposed Data Stores', desc: 'Buckets, blobs and images readable (or writable) from the public internet with no authentication — the fastest path to a data breach or leaked credentials.', types: ['Public data exposure', 'Public image share'] },
  { key: 'ingress', label: 'Open Network Ingress', desc: 'Security groups / NSGs / firewall rules that accept inbound traffic from any source (0.0.0.0/0), including exposed SSH and RDP — direct entry points for brute-force and exploitation.', types: ['Exposed SSH (22)', 'Exposed RDP (3389)', 'Open network ingress'] },
  { key: 'endpoints', label: 'Exposed Endpoints & Services', desc: 'Databases, functions and management planes published on public IPs or endpoints instead of private links — reachable and enumerable before any credential is needed.', types: ['Public service endpoint', 'Public IP address', 'Public function invoke'] }
];

// Over-permissive identity surface: the trust relationships an attacker probes
// to escalate once inside. Derived from failing/degraded IAM-family findings.
function _spReconIdentity(snap) {
  return snap.filter(function (r) {
    if (r.status !== 'FAIL') return false;
    var svc = (r.service || '').toLowerCase();
    var isIdentity = svc.indexOf('iam') >= 0 || svc.indexOf('azure ad') >= 0 || svc === 'ad';
    if (!isIdentity) return false;
    var t = (r.name + ' ' + (r.description || '')).toLowerCase();
    return /wildcard|overprivileged|admin|privilege|passrole|assume|inline polic|primitive role|service account key|domain-wide|mfa|password polic|access key|unused/.test(t);
  });
}

// Weighted exposure score (higher = more exposed / worse), capped at 100.
function _spExposureScore(items) {
  var w = { CRITICAL: 14, HIGH: 8, MEDIUM: 3, LOW: 1 };
  var s = 0;
  items.forEach(function (x) { s += (w[x.severity] || 1); });
  return Math.min(100, Math.round(s));
}
function _spExposureBand(score) {
  if (score >= 70) return { t: 'WIDE OPEN', c: '#dc2626' };
  if (score >= 40) return { t: 'ELEVATED', c: '#f97316' };
  if (score > 0) return { t: 'GUARDED', c: '#eab308' };
  return { t: 'HARDENED', c: '#22c55e' };
}

function _spRenderRecon(c) {
  var snap = _spBuildSnapshot();
  var exposed = [];
  snap.forEach(function (r) { if (r.status !== 'FAIL') return; var ex = _spClassifyExposure(r); if (ex) exposed.push({ r: r, type: ex.type, why: ex.why }); });
  var identity = _spReconIdentity(snap);

  // Assemble grouped view.
  var groups = _SP_RECON_GROUPS.map(function (g) {
    var items = exposed.filter(function (e) { return g.types.indexOf(e.type) >= 0; });
    items.sort(function (a, b) {
      var s = _SP_SEV_ORDER[a.r.severity] - _SP_SEV_ORDER[b.r.severity]; if (s) return s;
      var cl = _SP_CLOUD_ORDER[a.r.cloud] - _SP_CLOUD_ORDER[b.r.cloud]; if (cl) return cl;
      return a.r.id < b.r.id ? -1 : 1;
    });
    return { g: g, items: items };
  });
  identity.sort(function (a, b) {
    var s = _SP_SEV_ORDER[a.severity] - _SP_SEV_ORDER[b.severity]; if (s) return s;
    var cl = _SP_CLOUD_ORDER[a.cloud] - _SP_CLOUD_ORDER[b.cloud]; if (cl) return cl;
    return a.id < b.id ? -1 : 1;
  });

  // Score over reachable exposures + identity surface.
  var scored = exposed.map(function (e) { return e.r; }).concat(identity);
  var score = _spExposureScore(scored);
  var band = _spExposureBand(score);
  var crit = scored.filter(function (r) { return r.severity === 'CRITICAL'; }).length;

  var groupCard = function (label, desc, rowsHtml, count) {
    return '<div class="sp-card" style="margin-top:14px">' +
      '<div class="sp-card-h" style="display:flex;justify-content:space-between;align-items:center">' +
        '<span>' + esc(label) + '</span><span style="color:var(--txt)">' + count + '</span>' +
      '</div>' +
      '<p class="sp-why" style="max-width:none;margin:0 0 10px">' + esc(desc) + '</p>' +
      (count ?
        '<table class="sp-table"><thead><tr><th>Check</th><th>Cloud</th><th>What an attacker sees</th><th>Severity</th></tr></thead><tbody>' + rowsHtml + '</tbody></table>' :
        '<div class="sp-empty" style="padding:16px">Nothing exposed in this category.</div>') +
      '</div>';
  };

  var html =
    '<h2 class="sp-h2">External Attack Surface — Outside-In Recon</h2>' +
    '<p class="sp-sub">Reconnaissance view of everything reachable or observable from outside the accounts, derived from the checks you answered Fail. This is the map an attacker builds <b>before</b> authenticating — publicly-exposed resources grouped by perimeter type, plus the over-permissive identity surface that turns any foothold into full compromise. Close the widest categories first.</p>' +
    '<div class="sp-stat-tiles">' +
      _spStatTile(score + ' — ' + band.t, 'Exposure Score', band.c) +
      _spStatTile(scored.length, 'Reachable / Weak Assets', 'var(--acc)') +
      _spStatTile(crit, 'Critical Exposures', '#dc2626') +
      _spStatTile(exposed.length, 'Perimeter Findings', '#f97316') +
      _spStatTile(identity.length, 'Permissive Identities', '#eab308') +
    '</div>' +
    _spAnswerNote(snap);

  groups.forEach(function (grp) {
    var rows = grp.items.map(function (e) {
      return '<tr><td class="sp-mono">' + esc(e.r.id) + '<div class="sp-cell-sub">' + esc(e.r.service) + ' · ' + esc(e.r.name) + '</div></td>' +
        '<td>' + esc(e.r.cloud) + '</td>' +
        '<td>' + esc(e.type) + '<div class="sp-cell-sub">' + esc(e.why) + '</div></td>' +
        '<td><span class="sp-sev-badge" style="color:' + _spSevColor(e.r.severity) + ';background:' + _spSevBg(e.r.severity) + '">' + e.r.severity + '</span></td></tr>';
    }).join('');
    html += groupCard(grp.g.label, grp.g.desc, rows, grp.items.length);
  });

  // Identity surface card (own shape — no exposure "type").
  var idRows = identity.map(function (r) {
    return '<tr><td class="sp-mono">' + esc(r.id) + '<div class="sp-cell-sub">' + esc(r.service) + '</div></td>' +
      '<td>' + esc(r.cloud) + '</td>' +
      '<td>' + esc(r.name) + '<div class="sp-cell-sub">' + esc(r.description || '') + '</div></td>' +
      '<td><span class="sp-sev-badge" style="color:' + _spSevColor(r.severity) + ';background:' + _spSevBg(r.severity) + '">' + r.severity + '</span></td></tr>';
  }).join('');
  html += groupCard('Over-Permissive Identity & Trust', 'IAM roles, policies and directory settings an attacker abuses to escalate from an initial foothold — wildcard grants, missing MFA on privileged roles, stale keys and broad trust relationships. Not internet-visible, but the difference between a contained incident and full account takeover.', idRows, identity.length);

  c.innerHTML = html;
}

// ============================================================================
// OFFENSIVE TAB — SIMULATED ATTACK PATHS (wargaming; no live capability)
// ============================================================================
// SIMULATION ONLY. Each scenario chains real misconfiguration findings into a
// plausible attack path (public entry -> credential access -> privilege
// escalation -> lateral movement -> exfiltration). Every step names the specific
// check IDs that would enable it; at render time we look those IDs up in the
// live snapshot to show whether the enabling misconfig is actually failing, and
// derive a blast-radius / detection verdict. This is illustrative reasoning over
// existing findings to prioritise defense — never a real attack capability.
var _SP_ATTACK_SCENARIOS = [
  {
    id: 'aws-bucket-exfil', name: 'AWS: Public bucket to data exfiltration', cloud: 'AWS',
    tactic: 'Initial Access → Credential Access → Privilege Escalation → Exfiltration',
    foothold: 'An anonymous, internet-facing S3 bucket',
    impact: 'An unauthenticated attacker reads a public bucket, harvests credentials committed to it, assumes an over-privileged role, and exfiltrates data from across the account — potentially without leaving an audit trail.',
    steps: [
      { phase: 'Foothold', action: 'Enumerate and read the public S3 bucket anonymously from the internet.', ids: ['AWS-S3-001', 'AWS-S3-006'] },
      { phase: 'Credential Access', action: 'Recover long-lived access keys and config from unencrypted, unlogged objects in the bucket.', ids: ['AWS-S3-002', 'AWS-IAM-005'] },
      { phase: 'Privilege Escalation', action: 'Use the harvested keys against an over-privileged / wildcard IAM policy to grant admin.', ids: ['AWS-IAM-003', 'AWS-IAM-007'] },
      { phase: 'Lateral Movement', action: 'Reach a publicly-accessible RDS instance and additional data stores with the escalated role.', ids: ['AWS-RDS-001'] },
      { phase: 'Exfiltration', action: 'Bulk-copy data out of the account to attacker-controlled storage.', ids: ['AWS-S3-008'] }
    ],
    detectIds: ['AWS-CT-001', 'AWS-VPC-002']
  },
  {
    id: 'aws-ssh-pivot', name: 'AWS: Internet-exposed host to account takeover', cloud: 'AWS',
    tactic: 'Initial Access → Credential Access → Privilege Escalation → Lateral Movement',
    foothold: 'A security group exposing SSH (22) to 0.0.0.0/0',
    impact: 'An attacker brute-forces or exploits an internet-facing instance, steals its role credentials from the metadata service, escalates through a permissive policy and pivots across the VPC.',
    steps: [
      { phase: 'Foothold', action: 'Reach and compromise the instance via SSH open to the whole internet.', ids: ['AWS-EC2-001'] },
      { phase: 'Credential Access', action: 'Query the instance metadata service (IMDSv1) to steal the attached role credentials.', ids: ['AWS-EC2-005'] },
      { phase: 'Privilege Escalation', action: 'Abuse over-privileged / inline IAM policies attached to the role to widen access.', ids: ['AWS-IAM-003', 'AWS-IAM-006'] },
      { phase: 'Lateral Movement', action: 'Pivot across a flat VPC with permissive ingress to reach internal databases.', ids: ['AWS-VPC-003', 'AWS-RDS-001'] }
    ],
    detectIds: ['AWS-CT-001', 'AWS-VPC-002']
  },
  {
    id: 'az-nsg-sql', name: 'Azure: Open NSG to SQL & Key Vault breach', cloud: 'Azure',
    tactic: 'Initial Access → Discovery → Collection → Privilege Escalation',
    foothold: 'An NSG allowing any-source inbound / exposed management ports',
    impact: 'An attacker reaches a VM over an open NSG, discovers a SQL server on a public endpoint, pulls secrets from a network-open Key Vault, and escalates via a privileged role without MFA.',
    steps: [
      { phase: 'Foothold', action: 'Connect to an exposed VM through an NSG rule allowing traffic from any source.', ids: ['AZ-NSG-001', 'AZ-NSG-002'] },
      { phase: 'Discovery', action: 'Reach the VM public IP and enumerate reachable data services.', ids: ['AZ-VM-001'] },
      { phase: 'Collection', action: 'Query a SQL server whose public network access is enabled, and pull secrets from a network-open Key Vault.', ids: ['AZ-SQL-005', 'AZ-KV-003'] },
      { phase: 'Privilege Escalation', action: 'Take over a privileged directory role that is not protected by MFA / Conditional Access.', ids: ['AZ-AD-001'] }
    ],
    detectIds: ['AZ-SQL-001']
  },
  {
    id: 'gcp-bucket-project', name: 'GCP: Public bucket to project compromise', cloud: 'GCP',
    tactic: 'Initial Access → Credential Access → Privilege Escalation → Exfiltration',
    foothold: 'A Cloud Storage bucket granting access to allUsers',
    impact: 'An attacker reads a public GCS bucket, recovers a service-account key, abuses broad delegation to impersonate high-privilege identities, reaches a public Cloud SQL instance and exfiltrates — with data-access audit logging off.',
    steps: [
      { phase: 'Foothold', action: 'Read the public Cloud Storage bucket anonymously (allUsers / allAuthenticatedUsers).', ids: ['GCP-GCS-001', 'GCP-GCS-005'] },
      { phase: 'Credential Access', action: 'Recover a service-account key from the bucket contents.', ids: ['GCP-IAM-004'] },
      { phase: 'Privilege Escalation', action: 'Abuse broad / primitive IAM grants to impersonate a high-privilege service account.', ids: ['GCP-IAM-001'] },
      { phase: 'Lateral Movement', action: 'Connect to a Cloud SQL instance exposed on a public IP.', ids: ['GCP-SQL-001'] },
      { phase: 'Exfiltration', action: 'Export data out of the project to attacker-controlled storage.', ids: ['GCP-GCS-002'] }
    ],
    detectIds: ['GCP-LOG-003']
  }
];

function _spResolveFinding(id, snap) {
  var f = null;
  for (var i = 0; i < snap.length; i++) { if (snap[i].id === id) { f = snap[i]; break; } }
  return f || { id: id, name: id, service: '', cloud: '', severity: 'MEDIUM', status: 'N/A', resource: '-' };
}

// Evaluate a scenario against the live snapshot: which steps are actually
// enabled (an enabling misconfig is FAILing), and whether detection controls
// would catch it.
function _spEvalPath(scenario, snap) {
  var steps = scenario.steps.map(function (st) {
    var findings = st.ids.map(function (id) { return _spResolveFinding(id, snap); });
    var viable = findings.some(function (f) { return f.status === 'FAIL'; });
    var unknown = !viable && findings.some(function (f) { return f.status === 'UNANSWERED'; });
    return { st: st, findings: findings, viable: viable, partial: false, unknown: unknown };
  });
  var enabled = steps.filter(function (s) { return s.viable; }).length;
  var entryViable = steps[0] && steps[0].viable;
  var detect = scenario.detectIds.map(function (id) { return _spResolveFinding(id, snap); });
  var detectionGap = detect.some(function (f) { return f.status === 'FAIL'; });
  var detectUnknown = !detectionGap && detect.some(function (f) { return f.status === 'UNANSWERED'; });

  var verdict;
  if (!entryViable && steps[0] && steps[0].unknown) verdict = { t: 'UNKNOWN - ANSWER ENTRY CHECKS', k: 'warn', c: '#64748b' };
  else if (!entryViable) verdict = { t: 'CHAIN BLOCKED AT ENTRY', k: 'ok', c: '#22c55e' };
  else if (enabled === steps.length) verdict = { t: 'FULL CHAIN VIABLE', k: 'bad', c: '#dc2626' };
  else verdict = { t: 'PARTIAL CHAIN — ' + enabled + '/' + steps.length + ' STEPS VIABLE', k: 'warn', c: '#f97316' };

  return { steps: steps, enabled: enabled, entryViable: entryViable, detect: detect, detectionGap: detectionGap, detectUnknown: detectUnknown, verdict: verdict };
}

function _spRenderAttackPath(c) {
  var snap = _spBuildSnapshot();
  if (!_spAttackScenario || !_SP_ATTACK_SCENARIOS.some(function (s) { return s.id === _spAttackScenario; })) {
    _spAttackScenario = _SP_ATTACK_SCENARIOS[0].id;
  }
  var scenario = _SP_ATTACK_SCENARIOS.filter(function (s) { return s.id === _spAttackScenario; })[0];
  var ev = _spEvalPath(scenario, snap);

  var statusBadge = function (st) {
    return '<span class="sp-status-badge" style="color:' + _spStatusColor(st) + '">' + esc(st) + '</span>';
  };

  var stepCards = ev.steps.map(function (s, i) {
    var stateColor = s.viable ? '#dc2626' : s.unknown ? '#64748b' : '#22c55e';
    var stateLabel = s.viable ? 'ENABLING MISCONFIG PRESENT' : s.unknown ? 'NOT YET ANSWERED' : 'CONTROL HOLDS';
    var findingRows = s.findings.map(function (f) {
      return '<div style="display:flex;gap:8px;align-items:baseline;flex-wrap:wrap;margin-top:4px">' +
        statusBadge(f.status) +
        '<span class="sp-mono" style="font-size:.72rem">' + esc(f.id) + '</span>' +
        '<span class="sp-cell-sub" style="margin-top:0">' + esc(f.name) + '</span>' +
        '</div>';
    }).join('');
    var connector = i > 0 ? '<div style="text-align:center;color:var(--mut);font-size:1rem;line-height:1;margin:2px 0">&#8595;</div>' : '';
    return connector +
      '<div class="sp-card" style="border-left:3px solid ' + stateColor + '">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">' +
          '<strong style="font-size:.82rem;color:var(--txt)">Step ' + (i + 1) + ' — ' + esc(s.st.phase) + '</strong>' +
          '<span class="sp-sev-badge" style="color:' + stateColor + ';background:color-mix(in srgb,' + stateColor + ' 12%,transparent)">' + stateLabel + '</span>' +
        '</div>' +
        '<div class="sp-remed-desc" style="margin-top:6px">' + esc(s.st.action) + '</div>' +
        '<div style="margin-top:6px"><span class="sp-cell-sub" style="margin-top:0">Enabled by:</span>' + findingRows + '</div>' +
      '</div>';
  }).join('');

  var detectRows = ev.detect.map(function (f) {
    return '<div style="display:flex;gap:8px;align-items:baseline;flex-wrap:wrap;margin-top:4px">' +
      statusBadge(f.status) +
      '<span class="sp-mono" style="font-size:.72rem">' + esc(f.id) + '</span>' +
      '<span class="sp-cell-sub" style="margin-top:0">' + esc(f.name) + '</span></div>';
  }).join('');

  var detectVerdict = ev.detectUnknown
    ? { t: 'UNKNOWN', c: '#64748b', note: 'One or more logging / audit checks on this path have not been answered yet. Answer them in the cloud checklist tabs to evaluate detection.' }
    : ev.detectionGap
    ? { t: 'LIKELY UNDETECTED', c: '#dc2626', note: 'A logging / audit control on this path is failing — the attack could complete without generating a reliable trail. Restore audit logging first so the chain is at least observable.' }
    : { t: 'DETECTION LIKELY', c: '#22c55e', note: 'Audit / logging controls on this path are active — the activity would be recorded and is available for detection and response.' };

  c.innerHTML =
    '<h2 class="sp-h2">Simulated Attack Paths <span class="sp-sim-tag">Simulation only</span></h2>' +
    '<p class="sp-sub"><b>Illustrative reasoning over existing findings — no network calls, no exploitation.</b> Each scenario chains real misconfiguration checks into a plausible attack path and ties every step to the specific finding IDs that would enable it. Steps are evaluated against your checklist answers to show which would be viable and whether the attack would be detected. Use it to prioritise which misconfigurations to close first.</p>' +
    '<div class="sp-exp-filters">' +
      '<label class="sp-cell-sub" style="margin-top:0">Scenario</label>' +
      '<select class="sp-select" id="sp-ap-scenario">' +
        _SP_ATTACK_SCENARIOS.map(function (s) {
          return '<option value="' + esc(s.id) + '"' + (s.id === scenario.id ? ' selected' : '') + '>' + esc(s.name) + '</option>';
        }).join('') +
      '</select>' +
    '</div>' +
    _spAnswerNote(snap) +
    '<div class="sp-card" style="margin-bottom:14px">' +
      '<div class="sp-card-h">Scenario</div>' +
      '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px">' +
        '<span class="sp-legend-chip">Cloud <b>' + esc(scenario.cloud) + '</b></span>' +
        '<span class="sp-legend-chip">Foothold <b>' + esc(scenario.foothold) + '</b></span>' +
      '</div>' +
      '<div class="sp-why" style="max-width:none;margin-bottom:8px">' + esc(scenario.tactic) + '</div>' +
      '<div class="sp-stat-tiles">' +
        _spStatTile(ev.verdict.t, 'Blast-Radius Verdict', ev.verdict.c) +
        _spStatTile(ev.enabled + ' / ' + ev.steps.length, 'Viable Steps', 'var(--acc)') +
        _spStatTile(detectVerdict.t, 'Detection', detectVerdict.c) +
      '</div>' +
      '<div class="sp-remed-desc" style="margin-top:12px"><b>Impact:</b> ' + esc(scenario.impact) + '</div>' +
    '</div>' +
    '<h3 class="sp-h3">Attack chain</h3>' +
    stepCards +
    '<div class="sp-card" style="margin-top:14px;border-left:3px solid ' + detectVerdict.c + '">' +
      '<div class="sp-card-h">Detection &amp; blast radius</div>' +
      '<div class="sp-remed-desc">' + esc(detectVerdict.note) + '</div>' +
      '<div style="margin-top:8px"><span class="sp-cell-sub" style="margin-top:0">Controls that would catch this path:</span>' + (detectRows || '<div class="sp-cell-sub">None mapped.</div>') + '</div>' +
    '</div>';

  var sel = c.querySelector('#sp-ap-scenario');
  if (sel) sel.onchange = function () { _spAttackScenario = sel.value; _spRenderAttackPath(c); };
}

// ============================================================================
// INLINE CSS
// ============================================================================
var _spStyleId = 'sp-styles';
function _spInjectCSS() {
  if (document.getElementById(_spStyleId)) return;
  var style = document.createElement('style');
  style.id = _spStyleId;
  style.textContent = `
.sp-wrap{padding:0 4px;font-family:var(--font-body,system-ui,sans-serif)}
.sp-header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:12px}
.sp-title-row{display:flex;align-items:baseline;gap:12px}
.sp-title{margin:0;font-size:1.3rem;font-weight:800;letter-spacing:.04em;color:var(--txt)}
.sp-subtitle{font-size:.78rem;color:var(--mut);font-weight:500}
.sp-meta{display:flex;gap:16px;font-size:.72rem;color:var(--mut)}
.sp-meta-item{display:flex;align-items:center;gap:5px}
.sp-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.sp-tabs{display:flex;gap:2px;overflow-x:auto;border-bottom:2px solid var(--line);padding-bottom:0;scrollbar-width:none}
.sp-tabs::-webkit-scrollbar{display:none}
.sp-tab{padding:9px 14px;font-size:.76rem;font-weight:600;color:var(--mut);background:none;border:none;cursor:pointer;white-space:nowrap;border-bottom:2px solid transparent;margin-bottom:-2px;transition:color .15s,border-color .15s;font-family:inherit}
.sp-tab:hover{color:var(--txt)}
.sp-tab.on{color:var(--acc);border-bottom-color:var(--acc)}
.sp-h2{margin:0 0 8px;font-size:1rem;font-weight:700;color:var(--txt)}
.sp-h3{margin:16px 0 8px;font-size:.88rem;font-weight:700;color:var(--txt)}
.sp-sub{color:var(--mut);font-size:.82rem;margin:0 0 16px}
.sp-modenote{color:var(--mut);font-size:.72rem;margin:4px 0 10px;min-height:1em}
.sp-card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.sp-card-h{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin-bottom:12px}
.sp-grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.sp-grid-2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:900px){.sp-grid-3{grid-template-columns:1fr}.sp-grid-2{grid-template-columns:1fr}}
.sp-score-card{text-align:center}
.sp-gauge-wrap{width:120px;height:120px;margin:0 auto 8px}
.sp-gauge{width:100%;height:100%}
.sp-score-detail{font-size:.76rem;color:var(--mut)}
.sp-sev-bars{display:flex;flex-direction:column;gap:10px}
.sp-sev-row{display:flex;align-items:center;gap:8px}
.sp-sev-label{font-size:.68rem;font-weight:700;width:60px;text-align:right}
.sp-sev-bar-bg{flex:1;height:8px;background:var(--line);border-radius:4px;overflow:hidden}
.sp-sev-bar-fill{height:100%;border-radius:4px;transition:width .4s ease}
.sp-sev-cnt{font-size:.72rem;font-weight:600;color:var(--txt);width:24px;text-align:right}
.sp-trend{display:flex;align-items:flex-end;gap:6px;height:100px;padding-top:16px}
.sp-trend-bar{flex:1;border-radius:4px 4px 0 0;min-height:8px;position:relative;transition:height .4s ease}
.sp-trend-val{position:absolute;top:-16px;left:50%;transform:translateX(-50%);font-size:.6rem;font-weight:700;color:var(--mut)}
.sp-comp-bars{display:flex;flex-direction:column;gap:10px}
.sp-comp-row{display:flex;align-items:center;gap:8px}
.sp-comp-name{font-size:.72rem;font-weight:600;width:120px;color:var(--txt);flex-shrink:0}
.sp-comp-bar-bg{flex:1;height:8px;background:var(--line);border-radius:4px;overflow:hidden}
.sp-comp-bar-fill{height:100%;border-radius:4px;transition:width .4s ease}
.sp-comp-pct{font-size:.72rem;font-weight:700;color:var(--txt);width:32px;text-align:right}
.sp-svc-list{display:flex;flex-direction:column;gap:4px}
.sp-svc-row{display:flex;align-items:center;gap:8px;font-size:.76rem;padding:4px 0;border-bottom:1px solid var(--line)}
.sp-svc-name{font-weight:600;color:var(--txt);flex:1}
.sp-svc-pass{color:#22c55e;font-size:.72rem}.sp-svc-fail{font-size:.72rem}.sp-svc-total{color:var(--mut);font-size:.72rem}
.sp-table{width:100%;border-collapse:collapse;font-size:.78rem}
.sp-table th{text-align:left;font-weight:700;font-size:.68rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);padding:8px 10px;border-bottom:2px solid var(--line);background:color-mix(in srgb,var(--bg) 50%,var(--card));position:sticky;top:0}
.sp-table td{padding:7px 10px;border-bottom:1px solid var(--line);color:var(--txt);vertical-align:top}
.sp-table tr:hover td{background:color-mix(in srgb,var(--acc) 4%,transparent)}
.sp-mono{font-family:var(--font-mono,monospace);font-size:.74rem}
.sp-sev-badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:.65rem;font-weight:700;letter-spacing:.03em}
.sp-status-badge{font-weight:700;font-size:.72rem}
.sp-status{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.65rem;font-weight:700}
.sp-pass{background:rgba(34,197,94,.12);color:#22c55e}
.sp-fail{background:rgba(220,38,38,.12);color:#dc2626}
.sp-partial{background:rgba(234,179,8,.12);color:#eab308}
.sp-na{background:rgba(100,116,139,.1);color:#64748b}
.sp-empty{padding:32px;text-align:center;color:var(--mut);font-size:.82rem}
.sp-ok-msg{padding:16px;text-align:center;color:#22c55e;font-size:.82rem;background:rgba(34,197,94,.08);border-radius:8px;font-weight:600}
.sp-btn{padding:7px 16px;font-size:.78rem;font-weight:600;border-radius:4px;cursor:pointer;font-family:inherit;border:none;transition:background .15s,color .15s;display:inline-flex;align-items:center;gap:6px}
.sp-btn-primary{background:var(--acc);color:#fff}
.sp-btn-primary:hover{filter:brightness(1.1)}
.sp-btn-ghost{background:transparent;color:var(--txt);border:1px solid var(--line)}
.sp-btn-ghost:hover{border-color:var(--acc);color:var(--acc)}
.sp-btn-sm{padding:4px 10px;font-size:.72rem}
.sp-btn-active{border-color:var(--acc);color:var(--acc);background:color-mix(in srgb,var(--acc) 8%,transparent)}
.sp-chip{padding:4px 10px;font-size:.7rem;font-weight:600;border-radius:4px;border:1px solid var(--line);background:transparent;color:var(--mut);cursor:pointer;font-family:inherit;transition:all .15s;white-space:nowrap}
.sp-chip:hover{border-color:var(--acc);color:var(--acc)}
.sp-chip.on{background:color-mix(in srgb,var(--acc) 10%,transparent);border-color:var(--acc);color:var(--acc)}
.sp-service-chips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.sp-filter-row{display:flex;gap:8px;margin-bottom:12px}
.sp-select{padding:6px 10px;font-size:.76rem;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--txt);font-family:inherit;cursor:pointer}
.sp-textarea{width:100%;box-sizing:border-box;padding:12px;font-family:var(--font-mono,monospace);font-size:.78rem;line-height:1.6;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--txt);resize:vertical}
.sp-textarea:focus{outline:none;border-color:var(--acc)}
.sp-audit-header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:16px}
.sp-audit-info{display:flex;flex-direction:column;gap:4px}
.sp-audit-actions{display:flex;gap:8px}
.sp-check-cnt{font-size:.76rem;color:var(--mut)}
.sp-audit-summary{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.sp-sum-item{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 20px;text-align:center;flex:1;min-width:100px}
.sp-sum-n{display:block;font-size:1.4rem;font-weight:800;color:var(--txt)}
.sp-sum-l{font-size:.68rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;font-weight:600}
.sp-sum-pass .sp-sum-n{color:#22c55e}
.sp-sum-fail .sp-sum-n{color:#dc2626}
.sp-sum-warn .sp-sum-n{color:#f97316}
.sp-rec-list{display:flex;flex-direction:column;gap:10px;padding-top:12px}
.sp-rec-item{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}
.sp-rec-head{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.sp-rec-desc{font-size:.78rem;color:var(--mut);margin-bottom:6px}
.sp-rec-fix{font-size:.78rem;color:var(--acc);font-weight:500}
.sp-details-sum{cursor:pointer;font-size:.82rem;font-weight:600;color:var(--acc);padding:8px 0}
.sp-iam-controls{display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.sp-iam-samples{display:flex;gap:6px;flex-wrap:wrap}
.sp-iam-results{margin-top:16px}
.sp-iam-matrix{margin-top:16px}
.sp-matrix-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(100px,1fr));gap:8px}
.sp-matrix-cell{border:1px solid;border-radius:8px;padding:10px;text-align:center}
.sp-matrix-svc{font-size:.7rem;font-weight:600;color:var(--txt);margin-bottom:4px}
.sp-matrix-lvl{font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.sp-iam-legend{display:flex;gap:16px;font-size:.72rem;color:var(--mut)}
.sp-legend-item{display:flex;align-items:center;gap:5px}
.sp-legend-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.sp-comp-tabs{display:flex;gap:4px;margin-bottom:16px;flex-wrap:wrap}
.sp-comp-tab{padding:6px 14px;font-size:.74rem;font-weight:600;border-radius:4px;border:1px solid var(--line);background:transparent;color:var(--mut);cursor:pointer;font-family:inherit;transition:all .15s}
.sp-comp-tab:hover{border-color:var(--acc);color:var(--acc)}
.sp-comp-tab.on{background:color-mix(in srgb,var(--acc) 10%,transparent);border-color:var(--acc);color:var(--acc)}
.sp-comp-summary{display:flex;align-items:center;gap:24px;margin-bottom:20px;flex-wrap:wrap}
.sp-comp-score{width:80px;height:80px;border-radius:50%;border:3px solid;display:flex;flex-direction:column;align-items:center;justify-content:center;flex-shrink:0}
.sp-comp-pct-big{font-size:1.2rem;font-weight:800}
.sp-comp-pct-label{font-size:.6rem;color:var(--mut);text-transform:uppercase}
.sp-comp-stats{display:flex;gap:20px}
.sp-comp-stat{display:flex;flex-direction:column;align-items:center;gap:2px;font-size:.72rem;color:var(--mut)}
.sp-comp-stat-n{font-size:1.1rem;font-weight:800}
.sp-comp-actions{display:flex;gap:8px}
.sp-gap-analysis{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.sp-gap-item{padding:6px 0;font-size:.78rem;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.sp-gap-item:last-child{border-bottom:none}
.sp-gap-cat{color:var(--mut);font-size:.72rem}
.sp-tf-controls{display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.sp-tf-checks{font-size:.72rem;color:var(--mut);margin-left:auto}
.sp-tf-layout{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:800px){.sp-tf-layout{grid-template-columns:1fr}}
.sp-tf-label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin-bottom:8px}
.sp-tf-input{min-height:300px}
.sp-tf-results{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.sp-tf-summary{display:flex;gap:16px;margin-bottom:12px;font-size:.78rem}
.sp-tf-stat{display:flex;align-items:center;gap:4px}
.sp-tf-findings{display:flex;flex-direction:column;gap:10px}
.sp-tf-finding{border:1px solid var(--line);border-radius:8px;padding:10px;background:color-mix(in srgb,var(--bg) 50%,var(--card))}
.sp-tf-finding-head{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.sp-tf-finding-line{font-size:.7rem;color:var(--mut);font-family:var(--font-mono)}
.sp-tf-finding-issue{font-size:.8rem;font-weight:600;color:var(--txt);margin-bottom:4px}
.sp-tf-finding-code{font-family:var(--font-mono);font-size:.72rem;color:var(--acc);background:var(--card2,var(--card));padding:4px 8px;border-radius:4px;margin-bottom:6px;overflow-x:auto;white-space:pre}
.sp-tf-finding-fix{font-size:.74rem;color:var(--mut)}
.sp-stat-tiles{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.sp-stat-tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 18px;text-align:center;flex:1;min-width:110px}
.sp-stat-n{display:block;font-size:1.5rem;font-weight:800;line-height:1.1}
.sp-stat-l{font-size:.66rem;color:var(--mut);text-transform:uppercase;letter-spacing:.05em;font-weight:600}
.sp-cell-sub{font-size:.68rem;color:var(--mut);margin-top:2px;font-family:var(--font-body,system-ui,sans-serif)}
.sp-why{font-size:.74rem;color:var(--mut);max-width:420px}
.sp-chip-legend{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.sp-legend-chip{font-size:.7rem;color:var(--mut);border:1px solid var(--line);border-radius:12px;padding:3px 10px;background:color-mix(in srgb,var(--acc) 4%,transparent)}
.sp-legend-chip b{color:var(--txt)}
.sp-remed-list{display:flex;flex-direction:column;gap:12px}
.sp-remed-item{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.sp-remed-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}
.sp-remed-cloud{font-size:.66rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);border:1px solid var(--line);border-radius:4px;padding:1px 6px}
.sp-remed-title{font-size:.82rem;color:var(--txt)}
.sp-effort{margin-left:auto;font-size:.64rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:10px}
.sp-effort-low{color:#22c55e;background:rgba(34,197,94,.12)}
.sp-effort-medium{color:#eab308;background:rgba(234,179,8,.12)}
.sp-effort-high{color:#f97316;background:rgba(249,115,22,.12)}
.sp-remed-desc{font-size:.76rem;color:var(--mut);margin-bottom:4px}
.sp-remed-fix{font-size:.76rem;color:var(--acc);font-weight:500;margin-bottom:8px}
.sp-code-block{border:1px solid var(--line);border-radius:8px;overflow:hidden;background:color-mix(in srgb,var(--bg) 60%,var(--card))}
.sp-code-bar{display:flex;align-items:center;justify-content:space-between;padding:5px 10px;border-bottom:1px solid var(--line)}
.sp-code-lang{font-size:.64rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}
.sp-copy-btn{font-family:inherit;font-size:.66rem;font-weight:700;color:var(--txt);background:transparent;border:1px solid var(--line);border-radius:4px;padding:3px 10px;cursor:pointer;transition:all .15s}
.sp-copy-btn:hover{border-color:var(--acc);color:var(--acc)}
.sp-copy-btn.sp-copied{color:#22c55e;border-color:#22c55e}
.sp-code{margin:0;padding:10px 12px;font-family:var(--font-mono,monospace);font-size:.72rem;line-height:1.55;color:var(--txt);white-space:pre;overflow-x:auto}
.sp-sim-tag{font-size:.6rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:#eab308;background:rgba(234,179,8,.12);padding:2px 8px;border-radius:10px;vertical-align:middle;margin-left:6px}
.sp-trend-top{display:flex;align-items:baseline;gap:6px;margin-bottom:8px}
.sp-trend-now{font-size:1.8rem;font-weight:800;line-height:1}
.sp-trend-unit{font-size:.72rem;color:var(--mut)}
.sp-trend-delta{margin-left:auto;font-size:.74rem;font-weight:700}
.sp-spark{width:100%;height:auto;display:block}
.sp-trend-axis{display:flex;justify-content:space-between;font-size:.66rem;color:var(--mut);margin-top:6px}
.sp-exp-filters{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.sp-search{flex:1;min-width:200px;padding:7px 12px;font-size:.78rem;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--txt);font-family:inherit}
.sp-search:focus{outline:none;border-color:var(--acc)}
.sp-exp-count{font-size:.72rem;color:var(--mut);font-weight:600;margin-left:auto;white-space:nowrap}
  `;
  document.head.appendChild(style);
}

// ============================================================================
// EXPORTS
// ============================================================================
export function renderSpectre(main) {
  _spInjectCSS();
  if (Array.isArray(window._spectreTimers)) { window._spectreTimers.forEach(function (t) { clearTimeout(t); }); }
  window._spectreTimers = [];
  _spActiveTab = 'dashboard';
  _spTfFindings = null;
  _spTfSource = '';
  _spIamFindings = null;
  _spIamMatrix = null;
  _spSelectedPolicy = null;
  _spAuditFilter = { service: '', severity: '', status: '' };
  _spComplianceTab = 'cis';
  _spRemedEffort = '';
  _spExplorer = { cloud: '', severity: '', status: '', q: '' };
  _spAttackScenario = '';
  _spRender(main);
}

export function cleanupSpectre() {
  if (_spInterval) { clearInterval(_spInterval); _spInterval = null; }
  if (Array.isArray(window._spectreTimers)) { window._spectreTimers.forEach(function (t) { clearTimeout(t); }); window._spectreTimers = []; }
}
