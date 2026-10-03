// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Plain-English help for the cloud.js mini-tools. See help/README.md for the contract.
// These are for reviewing and hardening cloud/container systems you operate or are authorised to test.
export const HELP = {
  "cl-arn-parse": {
    what: "Splits an AWS ARN (Amazon Resource Name, the unique id string AWS gives every resource) into its parts: partition, service, region, account and resource.",
    when: "You have an ARN in a log or policy and want to see which account, region and resource it points at.",
    example: { arn: "arn:aws:s3:::example-bucket/path/key.txt" },
  },
  "cl-arn-build": {
    what: "Assembles a valid ARN from the parts you type in (partition, service, region, account, resource).",
    when: "You are writing an IAM policy and need a correctly formatted ARN for a resource.",
    example: { service: "iam", account: "123456789012", resource: "role/Deploy" },
  },
  "cl-akia-decode": {
    what: "Reads an AWS access key ID, tells you what kind of key it is from its 4-letter prefix, and works out which account number owns it. Everything is computed locally with no AWS call.",
    when: "You found an access key ID in code or logs and want to know its type and owning account. It cannot tell you the secret or whether the key still works.",
    example: { key: "AKIAIOSFODNN7EXAMPLE" },
  },
  "cl-aws-partition-ref": {
    what: "Lists the AWS partitions (aws, aws-cn, aws-us-gov) used in ARNs and explains each.",
    when: "You are writing ARNs or policies for GovCloud or China and need the right partition name.",
    example: { q: "gov" },
  },
  "cl-aws-region-ref": {
    what: "Looks up an AWS region code (like us-east-1) and its geographic name, or searches by place name.",
    when: "You see a region code and want its location, or you need the code for a city.",
    example: { q: "tokyo" },
  },
  "cl-iam-policy-lint": {
    what: "Scans an IAM policy in JSON and flags overly broad grants, such as Action or Resource set to the wildcard *, Allow with NotAction, or a public principal with no condition.",
    when: "You are reviewing an IAM policy and want a quick safety check for least-privilege problems. It is a heuristic, not a full authorization review.",
    example: { json: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' },
  },
  "cl-iam-policy-explain": {
    what: "Describes each statement of an IAM policy in plain English: who it applies to, whether it allows or denies, which actions and resources, and any conditions.",
    when: "You are handed an IAM policy JSON and want a readable summary of what it actually grants.",
    example: { json: '{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::example-bucket/*"}]}' },
  },
  "cl-iam-policy-build": {
    what: "Builds a least-privilege IAM policy document from a service effect, a list of actions, a resource ARN and an optional condition.",
    when: "You need a scoped IAM policy and want correct JSON rather than hand-writing it.",
    example: { actions: "s3:GetObject s3:PutObject", resource: "arn:aws:s3:::example-bucket/*", sid: "BucketRW" },
  },
  "cl-iam-condition-keys": {
    what: "A searchable reference of common global IAM condition keys (like aws:SourceIp or aws:MultiFactorAuthPresent) used to tighten policies.",
    when: "You want to restrict a policy by IP, MFA, organisation or region and need the right condition key.",
    example: { q: "mfa" },
  },
  "cl-managed-policy-risk": {
    what: "Lists broad AWS-managed policies (such as AdministratorAccess) and explains why each grants wide access.",
    when: "You are reviewing which managed policies are attached and want to spot the over-powerful ones.",
    example: { q: "admin" },
  },
  "cl-sts-assume-role": {
    what: "Builds an aws sts assume-role command from a role ARN and session name, with optional external ID, MFA and duration.",
    when: "You need to assume an IAM role from the CLI and want the full command with the right flags.",
    example: { arn: "arn:aws:iam::123456789012:role/Deploy", session: "deploy-session" },
  },
  "cl-s3-bucket-policy-explain": {
    what: "Explains an S3 bucket policy statement by statement and flags any that make the bucket or its objects public (principal set to *).",
    when: "You are checking whether an S3 bucket policy accidentally exposes data to everyone.",
    example: { json: '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::example-bucket/*"}]}' },
  },
  "cl-s3-policy-build": {
    what: "Generates an S3 bucket policy: either one that denies any non-HTTPS access, or one that grants a specific principal scoped read/write.",
    when: "You want a ready-made bucket policy to enforce TLS or to give one role access to a bucket.",
    example: { bucket: "example-bucket", template: "Deny insecure (non-TLS) transport" },
  },
  "cl-s3-canned-acl": {
    what: "Explains each S3 canned ACL (preset permission like private or public-read) and marks the ones that make data public.",
    when: "You are setting or reviewing an object/bucket ACL and want to know exactly what each preset grants.",
    example: { q: "public" },
  },
  "cl-s3-url-parse": {
    what: "Takes any form of S3 URL (s3://, the bucket-in-hostname style, or the path style) and pulls out the bucket, key and region.",
    when: "You have an S3 link and want to know which bucket and object it refers to.",
    example: { url: "https://example-bucket.s3.us-east-1.amazonaws.com/path/key.txt" },
  },
  "cl-s3-url-build": {
    what: "Builds the three S3 URL forms (s3://, virtual-hosted and path-style) for a bucket, key and region.",
    when: "You need a correctly formatted S3 URL to share or use in a tool.",
    example: { bucket: "example-bucket", key: "path/key.txt", region: "us-east-1" },
  },
  "cl-s3-name-validate": {
    what: "Checks a bucket name against the AWS S3 naming rules (length, allowed characters, no IP-like names, reserved prefixes) and lists any problems.",
    when: "You are about to create an S3 bucket and want to confirm the name is allowed.",
    example: { name: "my-example-bucket" },
  },
  "cl-s3-presigned-explain": {
    what: "Decodes the signed query parameters on a presigned S3 URL and tells you the signing key, scope, which headers were signed, and when the link expires.",
    when: "You found a presigned S3 URL and want to know how long it stays valid and what it was signed with.",
    example: { url: "https://example-bucket.s3.amazonaws.com/key.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLE/20240101/us-east-1/s3/aws4_request&X-Amz-Date=20240101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=abcd1234" },
  },
  "cl-sigv4-scope-parse": {
    what: "Parses an AWS SigV4 Authorization header and shows the credential scope (key, date, region, service), the signed headers and the signature.",
    when: "You are debugging a signed AWS request and want to read what the Authorization header claims.",
    example: { hdr: "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20240101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcd1234ef567890" },
  },
  "cl-ecr-url-parse": {
    what: "Parses an Amazon ECR (Elastic Container Registry) image URI into the account, region, repository and tag or digest.",
    when: "You have an ECR image reference and want to know which account and region hosts it.",
    example: { uri: "123456789012.dkr.ecr.us-east-1.amazonaws.com/app:1.2.3" },
  },
  "cl-vpc-subnet-plan": {
    what: "Splits a VPC CIDR block into equal subnets of the prefix you pick and shows each subnet's usable host range, accounting for the five addresses AWS reserves in every subnet.",
    when: "You are designing a VPC and need to carve it into subnets with correct usable ranges.",
    example: { cidr: "10.0.0.0/16", prefix: "24", limit: "4" },
  },
  "cl-vpc-reserved-ips": {
    what: "Lists the five IP addresses AWS reserves in a subnet (network, router, DNS, future, broadcast) and the first and last usable host.",
    when: "You are assigning fixed IPs in a subnet and need to avoid the reserved ones.",
    example: { cidr: "10.0.1.0/24" },
  },
  "cl-vpc-cidr-check": {
    what: "Checks whether a CIDR is allowed for an AWS VPC (prefix between /16 and /28) and whether it uses private RFC 1918 address space.",
    when: "You are choosing a CIDR for a new VPC and want to confirm it is valid and private.",
    example: { cidr: "10.0.0.0/16" },
  },
  "cl-cidr-overlap": {
    what: "Tells you whether two CIDR blocks overlap, and if so how, which matters because VPC peering is rejected when ranges overlap.",
    when: "You are about to peer or merge two networks and need to check their address ranges do not clash.",
    example: { a: "10.0.0.0/16", b: "10.0.5.0/24" },
  },
  "cl-sg-rule-explain": {
    what: "Explains one security-group rule (direction, protocol, ports, CIDR) and warns if it opens a sensitive service to the whole internet.",
    when: "You are reviewing a firewall rule and want to understand what it allows and whether it is risky.",
    example: { dir: "Inbound", proto: "tcp", from: "22", to: "22", cidr: "0.0.0.0/0" },
  },
  "cl-sg-audit": {
    what: "Reads a list of inbound rules (protocol, port and CIDR per line) and reports any sensitive ports left open to the whole internet.",
    when: "You have a set of security-group rules and want a quick exposure audit.",
    example: { rules: "tcp 22 0.0.0.0/0\ntcp 443 0.0.0.0/0\ntcp 3306 0.0.0.0/0" },
  },
  "cl-gcp-resource-parse": {
    what: "Parses a Google Cloud resource name (full or relative) into its service and the collection/id pairs along its path.",
    when: "You have a GCP resource name and want to see the project, zone and resource it points at.",
    example: { name: "//compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/vm1" },
  },
  "cl-gcp-resource-build": {
    what: "Builds a Google Cloud relative resource name from a project, location type, location and resource.",
    when: "You need a correctly formatted GCP resource name for an API call or policy.",
    example: { project: "my-project", locType: "zones", location: "us-central1-a", collection: "instances", id: "vm1" },
  },
  "cl-gcs-url-parse": {
    what: "Parses a Google Cloud Storage URL (gs:// or an https storage link) into the bucket and object name.",
    when: "You have a GCS link and want to know which bucket and object it refers to.",
    example: { url: "gs://example-bucket/path/object.txt" },
  },
  "cl-gcs-name-validate": {
    what: "Checks a bucket name against the Google Cloud Storage naming rules (length, characters, no goog/google, start and end with a letter or digit).",
    when: "You are about to create a GCS bucket and want to confirm the name is allowed.",
    example: { name: "my-example-bucket" },
  },
  "cl-gcp-iam-member-explain": {
    what: "Explains a GCP IAM member string (like user: or serviceAccount:) and warns when it is allUsers or allAuthenticatedUsers, which make a resource public.",
    when: "You are reviewing GCP IAM bindings and want to catch public or risky members.",
    example: { member: "serviceAccount:app@my-project.iam.gserviceaccount.com" },
  },
  "cl-gcr-parse": {
    what: "Parses a Google Artifact Registry or Container Registry image reference into its host, project, repository and image.",
    when: "You have a GCR or Artifact Registry image reference and want to break it into its parts.",
    example: { ref: "us-docker.pkg.dev/my-project/my-repo/app:1.0" },
  },
  "cl-gcp-sa-key-explain": {
    what: "Summarises a Google service account key JSON (project, client email, key id) and warns that downloaded keys are long-lived credentials.",
    when: "You found a service account key file and want to know which account it belongs to. Never commit such a file.",
    example: { json: '{"type":"service_account","project_id":"my-project","client_email":"app@my-project.iam.gserviceaccount.com","client_id":"123","private_key_id":"abc"}' },
  },
  "cl-azure-resourceid-parse": {
    what: "Parses an Azure resource ID into its subscription, resource group, provider and resource type/name.",
    when: "You have an Azure resource ID from a portal link or log and want to read its parts.",
    example: { id: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.Storage/storageAccounts/myacct" },
  },
  "cl-azure-resourceid-build": {
    what: "Builds an Azure resource ID from a subscription, resource group, provider, type and name.",
    when: "You need a correctly formatted Azure resource ID for a template or API call.",
    example: { sub: "00000000-0000-0000-0000-000000000000", rg: "my-rg", provider: "Microsoft.Storage", type: "storageAccounts", name: "myacct" },
  },
  "cl-azure-blob-url-parse": {
    what: "Parses an Azure Blob Storage URL into the storage account, container and blob name.",
    when: "You have a blob URL and want to know which account and container it refers to.",
    example: { url: "https://myacct.blob.core.windows.net/container/path/blob.txt" },
  },
  "cl-azure-sas-explain": {
    what: "Decodes an Azure Shared Access Signature (SAS) query string and shows the services, permissions, validity window and allowed IP/protocol it grants.",
    when: "You found a SAS token or URL and want to know what it allows and when it expires.",
    example: { sas: "sv=2022-11-02&ss=b&srt=co&sp=rl&se=2030-01-01T00:00:00Z&spr=https&sig=examplesignature" },
  },
  "cl-azure-storage-name-validate": {
    what: "Checks a name against Azure storage account rules (3 to 24 characters, lowercase letters and digits only).",
    when: "You are about to create an Azure storage account and want to confirm the name is allowed.",
    example: { name: "myexampleacct01" },
  },
  "cl-acr-parse": {
    what: "Parses an Azure Container Registry image reference into the registry, repository and tag or digest.",
    when: "You have an ACR image reference and want to break it into its parts.",
    example: { ref: "myregistry.azurecr.io/app/web:1.0" },
  },
  "cl-azure-rbac-roles-ref": {
    what: "Lists broad Azure built-in roles (Owner, Contributor and similar) and explains what each allows.",
    when: "You are reviewing Azure role assignments and want to understand the powerful ones.",
    example: { q: "owner" },
  },
  "cl-k8s-rbac-explain": {
    what: "Explains a Kubernetes RBAC rule (its API groups, resources and verbs) in plain English and flags dangerous grants like reading secrets or using the escalate verb.",
    when: "You are reviewing a Role or ClusterRole and want to know what it really permits.",
    example: { apiGroups: '""', resources: "secrets", verbs: "get,list" },
  },
  "cl-k8s-rbac-verbs-ref": {
    what: "A reference of Kubernetes RBAC verbs (get, list, create and so on) including the special escalate, bind and impersonate verbs.",
    when: "You are writing an RBAC rule and want to know what each verb allows.",
    example: { q: "escalate" },
  },
  "cl-k8s-rolebinding-build": {
    what: "Generates a namespaced Role and a matching RoleBinding YAML that grants the verbs you choose on the resources you choose to a subject.",
    when: "You need a least-privilege Role plus RoleBinding and want ready-to-apply YAML.",
    example: { ns: "default", roleName: "pod-reader", resources: "pods", verbs: "get,list,watch", subject: "app-sa" },
  },
  "cl-k8s-can-i": {
    what: "Builds a kubectl auth can-i command to test whether a user or service account is allowed to perform an action.",
    when: "You want to check what permissions a subject has in a cluster.",
    example: { verb: "get", resource: "pods", ns: "default" },
  },
  "cl-k8s-securitycontext": {
    what: "Reviews the securityContext settings you tick and reports which container hardening controls (run as non-root, no privilege escalation, dropped capabilities and so on) are missing or unsafe.",
    when: "You are hardening a pod and want to know which securityContext fields still need fixing.",
    example: { runAsNonRoot: false, privileged: true, allowPrivEsc: true },
  },
  "cl-k8s-securitycontext-yaml": {
    what: "Produces a hardened container securityContext YAML block that meets the restricted Pod Security Standard.",
    when: "You want a safe securityContext to paste into a pod or deployment spec.",
    example: { uid: "1000", readonly: true, netbind: false },
  },
  "cl-k8s-capabilities-ref": {
    what: "A reference of Linux capabilities for containers: the 14 Docker grants by default and the dangerous ones you should never add.",
    when: "You are choosing which capabilities to drop or add on a container and want to know what each does.",
    example: { q: "sys_admin" },
  },
  "cl-k8s-pod-security-standards": {
    what: "Summarises the three Kubernetes Pod Security Standards (Privileged, Baseline, Restricted) and the key controls each enforces.",
    when: "You are picking a Pod Security Standard for a namespace and want to see what each level requires.",
    example: { level: "Restricted" },
  },
  "cl-k8s-netpol-builder": {
    what: "Generates a Kubernetes NetworkPolicy YAML: a namespace default-deny, or a rule allowing traffic from one pod label to another.",
    when: "You are moving a namespace toward zero-trust networking and need a starter NetworkPolicy.",
    example: { ns: "default", template: "Default-deny all ingress" },
  },
  "cl-k8s-secret-coder": {
    what: "Encodes a key and value into the base64 data block a Kubernetes Secret uses, or decodes one back, and reminds you that base64 is not encryption.",
    when: "You are writing or reading a Kubernetes Secret and need the base64 data form. Remember Secrets are not encrypted by default.",
    example: { mode: "Encode (value -> data)", key: "password", value: "s3cr3t" },
  },
  "cl-k8s-hardening-flags": {
    what: "A CIS-aligned reference of important security flags for the Kubernetes API server, kubelet and etcd, with what each one does.",
    when: "You are hardening a self-managed cluster and want the key flags to set on each component.",
    example: { q: "kubelet" },
  },
  "cl-k8s-well-known-ports": {
    what: "A reference of the network ports used by Kubernetes control-plane and node components, useful when reviewing attack surface.",
    when: "You are firewalling a cluster or investigating an exposed port and want to know which component uses it.",
    example: { q: "etcd" },
  },
  "cl-k8s-seccomp-ref": {
    what: "Explains the seccompProfile types for pods and containers (RuntimeDefault, Localhost, Unconfined) and which to prefer.",
    when: "You are setting a seccomp profile on a workload and want to know the difference between the options.",
    example: { q: "default" },
  },
  "cl-dockerfile-lint": {
    what: "Scans a Dockerfile for security smells such as running as root, using the latest tag, ADD instead of COPY, piping downloads into a shell, and secrets baked into layers.",
    when: "You are reviewing a Dockerfile and want a quick security check before building. It is a heuristic, not a guarantee.",
    example: { text: "FROM ubuntu:latest\nADD . /app\nRUN curl http://example.com/install | bash" },
  },
  "cl-compose-lint": {
    what: "Scans a docker-compose file for risky settings like privileged, host networking or PID, mounting the Docker socket, added capabilities and latest tags.",
    when: "You are reviewing a docker-compose.yml and want to catch dangerous service settings.",
    example: { text: "services:\n  app:\n    image: nginx:latest\n    privileged: true" },
  },
  "cl-docker-run-explain": {
    what: "Reads a docker run command and explains its security-relevant flags, warning about dangerous ones like --privileged or mounting the Docker socket.",
    when: "You see a docker run command and want to know whether it weakens container isolation.",
    example: { cmd: "docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock nginx" },
  },
  "cl-docker-run-harden": {
    what: "Builds a docker run command with hardening flags: a non-root user, read-only filesystem, all capabilities dropped and no-new-privileges.",
    when: "You want a safer docker run command for an image instead of the permissive default.",
    example: { image: "nginx:1.27", user: "1000:1000", readonly: true, tmpfs: true },
  },
  "cl-image-ref-parse": {
    what: "Parses a container image reference into registry, repository, tag and digest, applying Docker's defaults (docker.io, the library/ prefix and the latest tag).",
    when: "You have an image name and want to see the full registry, repository and tag it resolves to.",
    example: { ref: "nginx:1.27" },
  },
  "cl-image-ref-build": {
    what: "Puts together a fully qualified image reference from a registry, repository, tag and optional digest.",
    when: "You need a complete image reference string for a manifest or pull command.",
    example: { registry: "ghcr.io", repo: "org/app", tag: "v1.0" },
  },
  "cl-oci-ref-validate": {
    what: "Checks the parts of an image reference against the OCI distribution grammar (repository component, tag and digest rules) and lists anything invalid.",
    when: "You are generating image references in a tool and want to confirm they are well-formed.",
    example: { ref: "registry.example.com/team/app:v1.0" },
  },
  "cl-oci-labels-ref": {
    what: "A reference of the standard org.opencontainers.image.* annotation keys (like source, version and revision) used to label images.",
    when: "You are adding labels to an image and want the standard key names.",
    example: { q: "source" },
  },
  "cl-trivy-builder": {
    what: "Builds a trivy command to scan a container image, a filesystem, an infrastructure-as-code config or a repository, with the severities you choose.",
    when: "You want to scan an image or project for vulnerabilities and need the right trivy command.",
    example: { mode: "image", target: "nginx:1.27", severity: "HIGH,CRITICAL" },
  },
  "cl-container-escape-ref": {
    what: "A defensive reference of common container breakout vectors (privileged containers, Docker socket mounts, host namespaces and so on) with how to prevent each.",
    when: "You are hardening containers and want to understand and close the usual escape routes.",
    example: { q: "socket" },
  },
  "cl-tf-address-parse": {
    what: "Parses a Terraform resource address into its module path, resource type, name and index key (from count or for_each).",
    when: "You see a resource address in a plan or state and want to read its parts.",
    example: { addr: 'module.net.aws_subnet.private["a"]' },
  },
  "cl-hcl-var-extract": {
    what: "Scans Terraform HCL code and lists every var., local., data. and module. reference it uses.",
    when: "You want to see which variables, locals, data sources and module outputs a block depends on.",
    example: { text: 'resource "aws_instance" "x" {\n  ami = var.ami_id\n  subnet_id = module.net.subnet_id\n}' },
  },
  "cl-imds-ssrf-explain": {
    what: "Explains the AWS, GCP and Azure instance metadata endpoints and how to defend them against SSRF (server-side request forgery, where a tricked server fetches the metadata for an attacker).",
    when: "You are learning about or defending against cloud metadata SSRF and want the key facts per provider.",
    example: { cloud: "AWS" },
  },
  "cl-imds-paths-ref": {
    what: "A reference of notable AWS instance metadata paths, so you understand what a metadata SSRF could expose (especially the role credentials path).",
    when: "You are reviewing SSRF risk on EC2 and want to know which metadata paths matter.",
    example: { q: "credentials" },
  },
  "cl-imdsv2-token": {
    what: "Builds the two curl commands for IMDSv2: first fetch a session token, then use it to read a metadata path.",
    when: "You need to read EC2 instance metadata on an instance that requires IMDSv2.",
    example: { path: "/latest/meta-data/instance-id", ttl: "21600" },
  },
  "cl-cloud-misconfig-checklist": {
    what: "A searchable checklist of high-impact cloud misconfigurations (public buckets, open security groups, wildcard IAM and more) with the consequence of each.",
    when: "You are auditing a cloud account and want a reminder of the usual serious misconfigurations to check.",
    example: { q: "s3" },
  },
};
