// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Azure Security Reference — comprehensive coverage of Azure security services,
// Entra ID attacks, misconfigurations, and hardening.

export const AZURE_SERVICES = [
  {
    service: "Entra ID (Azure AD)",
    description: "Identity and access management for Azure and Microsoft 365. Central to all Azure security — compromising Entra ID compromises everything.",
    misconfigurations: [
      { id: "AAD-001", title: "No Conditional Access policies", severity: "critical", description: "Without Conditional Access, there are no controls on how and where users authenticate — no MFA requirements, no device compliance checks, no location restrictions.", remediation: "Create Conditional Access policies requiring MFA for all users, blocking legacy authentication, and requiring compliant devices for sensitive apps." },
      { id: "AAD-002", title: "Legacy authentication not blocked", severity: "high", description: "Legacy protocols (IMAP, POP3, SMTP, ActiveSync basic auth) don't support MFA and are prime targets for password spray attacks.", remediation: "Block legacy authentication via Conditional Access policy." },
      { id: "AAD-003", title: "No break-glass accounts", severity: "high", description: "If all admin accounts are locked out (Conditional Access misconfiguration, MFA issues), there's no way to recover access.", remediation: "Create 2 break-glass accounts excluded from Conditional Access, with strong passwords, hardware FIDO2 keys, and monitoring alerts." },
      { id: "AAD-004", title: "Too many Global Administrators", severity: "high", description: "More than 4-5 Global Admins increases the attack surface. Each is a potential target for credential theft.", remediation: "Limit Global Admins to 2-4. Use PIM (Privileged Identity Management) for just-in-time activation." },
      { id: "AAD-005", title: "PIM not enabled for privileged roles", severity: "high", description: "Permanent role assignments mean admin privileges are always active, even when not needed.", remediation: "Enable PIM and convert permanent assignments to eligible. Require justification and approval for activation." },
      { id: "AAD-006", title: "Self-service password reset without strong verification", severity: "medium", description: "SSPR with only email or phone verification can be bypassed via SIM swapping or email compromise.", remediation: "Require 2 verification methods for SSPR. Use Microsoft Authenticator and security questions." },
      { id: "AAD-007", title: "Guest user access not restricted", severity: "medium", description: "Default guest settings allow external users to enumerate the directory, see group memberships, and read user properties.", remediation: "Set guest user access restrictions to 'Most restrictive'. Limit who can invite guests." },
      { id: "AAD-008", title: "App registrations allowed by all users", severity: "medium", description: "Any user can register applications in Entra ID, creating service principals that may be granted excessive permissions.", remediation: "Restrict app registrations to admins. Review existing app registrations for unused or overprivileged apps." },
      { id: "AAD-009", title: "Consent framework allows user consent", severity: "high", description: "Users can consent to third-party apps requesting dangerous permissions (Mail.Read, Files.ReadWrite) without admin approval.", remediation: "Disable user consent. Require admin consent for all apps. Create an admin consent workflow." },
      { id: "AAD-010", title: "No sign-in risk policies", severity: "high", description: "Without Identity Protection risk policies, compromised credentials and anomalous sign-ins aren't automatically blocked.", remediation: "Enable sign-in risk policy (block high risk, MFA for medium). Enable user risk policy (require password change for high risk)." }
    ],
    attacks: [
      { name: "Password Spray", description: "Try a small number of commonly used passwords against many accounts to avoid lockout thresholds.", tools: ["MSOLSpray", "SprayingToolkit", "Ruler", "o365spray"], mitre: "T1110.003" },
      { name: "Consent Phishing (Illicit Consent Grant)", description: "Trick a user into granting OAuth permissions to a malicious app that can then read their email, files, and contacts.", tools: ["365-Stealer", "o365-attack-toolkit"], mitre: "T1550.001" },
      { name: "Token Theft (Primary Refresh Token)", description: "Steal the PRT from a device to get persistent access to all Azure/M365 resources without credentials.", tools: ["ROADtools", "AADInternals", "Mimikatz"], mitre: "T1528" },
      { name: "MFA Fatigue / Push Bombing", description: "Send repeated MFA push notifications until the user accidentally approves one.", tools: ["Custom scripts"], mitre: "T1621" },
      { name: "Device Code Phishing", description: "Trick a user into entering a device code on the Microsoft login page, granting the attacker an access token.", tools: ["TokenTactics", "DeviceCodePhishing"], mitre: "T1566" },
      { name: "Tenant Enumeration", description: "Determine if a domain uses Azure/M365, enumerate tenant information, and discover valid usernames.", tools: ["AADInternals", "o365creeper", "TeamFiltration"], mitre: "T1589" },
      { name: "Azure AD Connect Exploitation", description: "Compromise the on-premises AD Connect server to extract sync credentials and perform DCSync or password changes.", tools: ["AADInternals", "adconnectdump"], mitre: "T1003" },
      { name: "Managed Identity Abuse", description: "From a compromised Azure resource (VM, App Service, Function), query the IMDS to get managed identity tokens for accessing other Azure resources.", tools: ["curl to 169.254.169.254 or MSI endpoint"], mitre: "T1552.005" }
    ],
    hardening: [
      "Enable Conditional Access with MFA for all users",
      "Block legacy authentication protocols",
      "Enable PIM for all privileged roles",
      "Limit Global Admins to 2-4 with break-glass accounts",
      "Disable user consent to applications",
      "Enable Identity Protection risk policies",
      "Configure sign-in frequency and persistent browser policies",
      "Restrict guest access and external collaboration",
      "Enable continuous access evaluation (CAE)",
      "Monitor risky sign-ins and users via Identity Protection",
      "Use FIDO2 security keys or Windows Hello for passwordless authentication",
      "Review app registrations and enterprise applications quarterly"
    ],
    auditCommands: [
      "az ad user list --query '[].{UPN:userPrincipalName,Enabled:accountEnabled}'",
      "az ad group list --query '[].{Name:displayName,Members:length(members)}'",
      "az ad sp list --all --query '[?servicePrincipalType==`Application`].{Name:displayName,AppId:appId}'",
      "az role assignment list --all --query '[?roleDefinitionName==`Owner` || roleDefinitionName==`Contributor`]'",
      "az ad user list --query '[?assignedPlans[?servicePlanId==`xxx`]]' # check license assignments"
    ]
  },
  {
    service: "Azure Key Vault",
    description: "Secure storage for secrets, certificates, and encryption keys. Central to secrets management in Azure.",
    misconfigurations: [
      { id: "KV-001", title: "Access policies too permissive", severity: "high", description: "Access policies granting all permissions (get, list, set, delete, backup, restore, recover, purge) to broad groups.", remediation: "Use RBAC (recommended) or scope access policies to specific permissions per principal." },
      { id: "KV-002", title: "Soft delete disabled", severity: "high", description: "Without soft delete, secrets and keys are permanently lost when deleted (accidental or malicious).", remediation: "Enable soft delete and purge protection. Both are now enabled by default for new vaults." },
      { id: "KV-003", title: "No network restrictions", severity: "medium", description: "Key Vault accessible from any network, including the public internet.", remediation: "Enable firewall rules. Allow access only from specific VNets and IP addresses." },
      { id: "KV-004", title: "Secret rotation not implemented", severity: "high", description: "Secrets stored indefinitely without rotation remain valid after potential compromise.", remediation: "Implement secret rotation using Event Grid notifications and automation." },
      { id: "KV-005", title: "Diagnostic logging not enabled", severity: "medium", description: "Without diagnostic logs, access to secrets and keys cannot be audited.", remediation: "Enable diagnostic logging to Log Analytics workspace or Storage Account." },
      { id: "KV-006", title: "RBAC not used (legacy access policies)", severity: "medium", description: "Access policies are vault-level only and don't support conditions. RBAC offers fine-grained per-secret permissions.", remediation: "Migrate from vault access policies to Azure RBAC for Key Vault." }
    ],
    auditCommands: [
      "az keyvault list --query '[].{Name:name,RBAC:properties.enableRbacAuthorization,SoftDelete:properties.enableSoftDelete}'",
      "az keyvault secret list --vault-name VAULT --query '[].{Name:name,Enabled:attributes.enabled,Expires:attributes.expires}'",
      "az keyvault show --name VAULT --query '{Network:properties.networkAcls,PurgeProtection:properties.enablePurgeProtection}'"
    ]
  },
  {
    service: "Azure Virtual Machines",
    description: "IaaS compute instances. Security concerns mirror EC2: network exposure, identity, patching, and data protection.",
    misconfigurations: [
      { id: "VM-001", title: "NSG allows RDP/SSH from any source", severity: "critical", description: "Network Security Group rules allowing port 3389 (RDP) or 22 (SSH) from 0.0.0.0/0 or * expose VMs to brute-force attacks.", remediation: "Restrict to specific IPs. Use Azure Bastion or Just-In-Time VM Access instead." },
      { id: "VM-002", title: "Just-In-Time access not enabled", severity: "high", description: "Management ports (SSH, RDP) are permanently open instead of being opened on-demand for a limited time.", remediation: "Enable JIT VM Access in Microsoft Defender for Cloud." },
      { id: "VM-003", title: "No managed identity (using stored credentials)", severity: "high", description: "Applications on VMs use hardcoded credentials or configuration files instead of Azure Managed Identity for authentication.", remediation: "Enable system-assigned or user-assigned managed identity. Use DefaultAzureCredential in code." },
      { id: "VM-004", title: "Disk encryption not enabled", severity: "high", description: "OS and data disks not encrypted at rest using Azure Disk Encryption (ADE) or Server-Side Encryption with CMK.", remediation: "Enable Azure Disk Encryption (BitLocker for Windows, dm-crypt for Linux) or SSE with customer-managed keys." },
      { id: "VM-005", title: "No update management", severity: "high", description: "VMs without automated patching accumulate unpatched vulnerabilities over time.", remediation: "Enable Azure Update Manager or Azure Automation Update Management for automated patching." },
      { id: "VM-006", title: "Public IP directly on VM", severity: "medium", description: "VMs with public IPs are directly exposed. Should be behind a load balancer, Application Gateway, or Azure Firewall.", remediation: "Remove public IPs. Use Azure Bastion for management and load balancers for applications." },
      { id: "VM-007", title: "Extensions from untrusted publishers", severity: "medium", description: "VM extensions run with elevated privileges and can execute arbitrary code on the VM.", remediation: "Review installed extensions. Only use extensions from Microsoft or verified publishers." },
      { id: "VM-008", title: "Boot diagnostics stored in accessible storage", severity: "low", description: "Boot diagnostics screenshots and serial console logs may contain sensitive information.", remediation: "Use managed storage accounts for boot diagnostics. Restrict access to the storage account." }
    ],
    attacks: [
      { name: "Managed Identity token theft", description: "From a compromised VM, query the Azure IMDS to get an access token for the VM's managed identity.", mitre: "T1552.005", steps: ["curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H 'Metadata: true'", "Use the access_token to call Azure Resource Manager APIs"] },
      { name: "Custom Script Extension abuse", description: "An attacker with VM Contributor can run arbitrary code on a VM by deploying a Custom Script Extension.", mitre: "T1059", steps: ["az vm extension set --resource-group RG --vm-name VM --name CustomScriptExtension --publisher Microsoft.Compute --settings '{\"commandToExecute\":\"whoami\"}'"] },
      { name: "Serial Console access", description: "Azure Serial Console provides direct console access to a VM, bypassing network security controls.", mitre: "T1021", steps: ["Access serial console via Azure Portal", "Login with local credentials", "No NSG or firewall rules apply to serial console"] }
    ],
    hardening: [
      "Use Azure Bastion instead of public RDP/SSH",
      "Enable Just-In-Time VM Access",
      "Use Managed Identity instead of stored credentials",
      "Enable disk encryption (ADE or SSE with CMK)",
      "Configure automated patching with Update Manager",
      "Remove public IPs from VMs",
      "Use NSG flow logs for network monitoring",
      "Enable Microsoft Defender for Servers",
      "Restrict VM extensions to trusted publishers",
      "Enable boot diagnostics with managed storage"
    ],
    auditCommands: [
      "az vm list --query '[].{Name:name,RG:resourceGroup,Size:hardwareProfile.vmSize}'",
      "az vm list-ip-addresses --query '[].{VM:virtualMachine.name,PublicIP:virtualMachine.network.publicIpAddresses[0].ipAddress}'",
      "az vm encryption show --resource-group RG --name VM",
      "az network nsg list --query '[].{Name:name,Rules:securityRules[?direction==`Inbound`&&access==`Allow`].{Port:destinationPortRange,Source:sourceAddressPrefix}}'"
    ]
  },
  {
    service: "Azure Storage",
    description: "Blob, File, Table, and Queue storage. Similar to S3 — public access and weak authentication are the main risks.",
    misconfigurations: [
      { id: "STOR-001", title: "Public blob access enabled", severity: "critical", description: "Storage account allows public access to blobs, potentially exposing sensitive data.", remediation: "Disable public blob access at the storage account level." },
      { id: "STOR-002", title: "Shared key authorization enabled", severity: "high", description: "Storage account keys provide full access and are long-lived. If leaked, all data is compromised.", remediation: "Disable shared key authorization. Use Entra ID (Azure AD) authentication with RBAC." },
      { id: "STOR-003", title: "HTTPS not enforced", severity: "medium", description: "Storage account accepts HTTP connections, allowing data interception.", remediation: "Enable 'Secure transfer required' to enforce HTTPS." },
      { id: "STOR-004", title: "No private endpoint", severity: "medium", description: "Storage account accessible over the public internet instead of through private endpoints.", remediation: "Create private endpoints for storage. Disable public network access." },
      { id: "STOR-005", title: "Soft delete not enabled for blobs", severity: "medium", description: "Deleted blobs cannot be recovered without soft delete, making ransomware and accidental deletion permanent.", remediation: "Enable soft delete for blobs with 30+ day retention." },
      { id: "STOR-006", title: "SAS tokens with excessive scope", severity: "high", description: "Shared Access Signature tokens with broad permissions, long expiry, or no IP restrictions can be abused if leaked.", remediation: "Use short-lived SAS tokens with minimal permissions. Prefer user delegation SAS over account SAS." },
      { id: "STOR-007", title: "No immutability policies for compliance data", severity: "medium", description: "Compliance data without WORM (Write Once Read Many) policies can be modified or deleted.", remediation: "Enable immutable storage with time-based retention or legal hold policies." },
      { id: "STOR-008", title: "Diagnostic logging not enabled", severity: "medium", description: "Without storage analytics logging, access to storage cannot be audited.", remediation: "Enable diagnostic logging to Log Analytics or a separate storage account." }
    ],
    auditCommands: [
      "az storage account list --query '[].{Name:name,PublicAccess:allowBlobPublicAccess,HTTPS:enableHttpsTrafficOnly,KeyAccess:allowSharedKeyAccess}'",
      "az storage account show --name ACCOUNT --query '{NetworkRules:networkRuleSet,Encryption:encryption}'",
      "az storage container list --account-name ACCOUNT --query '[].{Name:name,PublicAccess:properties.publicAccess}'"
    ]
  },
  {
    service: "Microsoft Defender for Cloud",
    description: "Cloud Security Posture Management (CSPM) and Cloud Workload Protection Platform (CWPP) for Azure, AWS, and GCP.",
    key_features: [
      "Secure Score — prioritized security recommendations",
      "Regulatory compliance dashboard (CIS, PCI, ISO, NIST)",
      "Attack path analysis — visualize multi-step attack chains",
      "Cloud security graph — query relationships between resources",
      "Defender plans: Servers, App Service, Databases, Storage, Containers, Key Vault, DNS, ARM",
      "Threat protection with real-time alerts",
      "Integration with Microsoft Sentinel for SIEM"
    ],
    auditCommands: [
      "az security assessment list --query '[?status.code==`Unhealthy`].{Name:displayName,Severity:metadata.severity}'",
      "az security secure-score-controls list --query '[].{Control:displayName,Score:current,Max:max}'",
      "az security alert list --query '[?status==`Active`].{Name:alertDisplayName,Severity:severity}'"
    ]
  }
];

export const AZURE_RBAC_ESCALATION = [
  { role: "Owner", risk: "critical", description: "Full access to all resources including the ability to assign RBAC roles. Can modify any resource and grant others the same level of access." },
  { role: "User Access Administrator", risk: "critical", description: "Can manage RBAC role assignments. An attacker with this role can grant themselves Owner on any resource." },
  { role: "Contributor", risk: "high", description: "Full access to all resources except RBAC assignments. Can create VMs, deploy code, modify data, and exfiltrate information." },
  { role: "Virtual Machine Contributor", risk: "high", description: "Can manage VMs including running Custom Script Extensions, which execute code as root/SYSTEM on the VM." },
  { role: "Automation Contributor", risk: "high", description: "Can create and run Automation runbooks that execute with the Automation Account's managed identity or Run As account." },
  { role: "Logic App Contributor", risk: "medium", description: "Can create Logic Apps that use managed identity to access other resources." },
  { role: "Key Vault Administrator", risk: "critical", description: "Full access to all secrets, keys, and certificates in Key Vault." },
  { role: "Storage Blob Data Owner", risk: "high", description: "Full access to blob storage data. Can read, modify, and delete all blobs." },
  { role: "Website Contributor", risk: "high", description: "Can manage App Service apps including deploying code and accessing application settings (which often contain secrets)." }
];

export const AZURE_TOOLS = [
  { name: "ROADtools", description: "Framework for Azure AD/Entra ID reconnaissance and data gathering. Includes ROADrecon (data collection) and ROADlib (library).", usage: "roadrecon auth -u USER -p PASS && roadrecon gather && roadrecon gui" },
  { name: "AADInternals", description: "PowerShell module for Azure AD and M365 administration, reconnaissance, and attacks. Includes tenant enumeration, token manipulation, and AD Connect exploitation.", usage: "Import-Module AADInternals; Get-AADIntTenantDetails" },
  { name: "AzureHound", description: "BloodHound data collector for Azure. Maps relationships between users, groups, apps, service principals, and resources for attack path analysis.", usage: "azurehound list -t TENANT_ID -u USER -p PASS -o output.json" },
  { name: "MicroBurst", description: "PowerShell toolkit for Azure security assessment. Includes subscription enumeration, key vault access, storage account discovery, and more.", usage: "Import-Module MicroBurst; Invoke-EnumerateAzureBlobs -Base COMPANY" },
  { name: "PowerZure", description: "PowerShell framework for Azure exploitation. Focuses on operational security and covers common Azure attack patterns.", usage: "Import-Module PowerZure; Get-AzureTargets" },
  { name: "ScoutSuite", description: "Multi-cloud security auditing tool. Analyzes Azure configuration and generates HTML reports with findings.", usage: "scout azure --cli" },
  { name: "Prowler", description: "Security assessment tool for AWS and Azure. Checks against CIS benchmarks and custom security checks.", usage: "prowler azure --sp-env-auth" },
  { name: "TokenTactics", description: "Azure AD token manipulation and abuse toolkit. Supports device code phishing, token refresh, and continuous access evaluation bypass.", usage: "Import-Module TokenTactics; Get-AzureToken -Client MSGraph" },
  { name: "GraphRunner", description: "Post-exploitation tool for Microsoft Graph API. Enumerates users, groups, emails, OneDrive files, Teams messages after gaining access.", usage: "Import-Module GraphRunner; Invoke-GraphRecon -Tokens $tokens" },
  { name: "TeamFiltration", description: "Cross-platform tool for M365 credential attacks. Supports password spraying, enumeration, exfiltration, and backdoor modules.", usage: "TeamFiltration --outpath ./output --enum --validate-login" }
];
