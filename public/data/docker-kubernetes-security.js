// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Docker & Kubernetes Security Reference — container security, escapes, RBAC, and hardening.

export const DOCKERFILE_BEST_PRACTICES = [
  { id: "DF-001", bad: "FROM ubuntu:latest", good: "FROM ubuntu:22.04@sha256:abc123...", rule: "Pin base image to specific version and digest", severity: "high", reason: "latest tag can change unexpectedly, introducing vulnerabilities or breaking changes. Digest pinning ensures reproducibility." },
  { id: "DF-002", bad: "RUN apt-get update && apt-get install -y curl wget vim nano", good: "RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*", rule: "Install only required packages, clean up cache", severity: "medium", reason: "Unnecessary packages increase attack surface. Cache files waste space." },
  { id: "DF-003", bad: "USER root", good: "RUN addgroup --system app && adduser --system --ingroup app app\nUSER app", rule: "Run as non-root user", severity: "critical", reason: "Root in container often means root on host. Container escapes are trivially exploitable as root." },
  { id: "DF-004", bad: "COPY . /app", good: "COPY --chown=app:app src/ /app/src/\nCOPY --chown=app:app package*.json /app/", rule: "Copy only needed files, set ownership", severity: "medium", reason: "Copying everything includes .git, secrets, test files. Use .dockerignore for broader protection." },
  { id: "DF-005", bad: "ENV DB_PASSWORD=supersecret123", good: "# Use runtime secrets: docker run -e DB_PASSWORD or Docker secrets", rule: "Never hardcode secrets in Dockerfile", severity: "critical", reason: "Environment variables in Dockerfile are baked into the image layer and visible to anyone with image access." },
  { id: "DF-006", bad: "RUN chmod 777 /app", good: "RUN chmod 550 /app && chmod 440 /app/config/*", rule: "Use restrictive file permissions", severity: "medium", reason: "World-writable directories allow any process to modify application code or configs." },
  { id: "DF-007", bad: "EXPOSE 22\nRUN apt-get install -y openssh-server", good: "# SSH not needed — use docker exec or kubectl exec", rule: "Don't install SSH in containers", severity: "high", reason: "SSH adds attack surface and management complexity. Use orchestrator tools for access." },
  { id: "DF-008", bad: "FROM node:18\n# ... build steps ...\n# Final image includes build tools", good: "FROM node:18 AS build\nRUN npm ci && npm run build\nFROM node:18-alpine\nCOPY --from=build /app/dist ./dist", rule: "Use multi-stage builds", severity: "medium", reason: "Build tools, compilers, and dev dependencies in production images increase attack surface." },
  { id: "DF-009", bad: "RUN curl https://example.com/setup.sh | bash", good: "COPY setup.sh /tmp/\nRUN bash /tmp/setup.sh && rm /tmp/setup.sh", rule: "Don't pipe scripts from the internet", severity: "high", reason: "Piping to bash from remote URLs is vulnerable to MITM attacks and remote code changes." },
  { id: "DF-010", bad: "HEALTHCHECK NONE", good: "HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD curl -f http://localhost:8080/health || exit 1", rule: "Define health checks", severity: "low", reason: "Health checks enable orchestrators to detect and restart unhealthy containers." },
  { id: "DF-011", bad: "RUN pip install -r requirements.txt", good: "RUN pip install --no-cache-dir --require-hashes -r requirements.txt", rule: "Verify package integrity", severity: "medium", reason: "Without hash verification, compromised packages can be silently installed." },
  { id: "DF-012", bad: "ADD https://example.com/app.tar.gz /app/", good: "RUN curl -sSL https://example.com/app.tar.gz -o /tmp/app.tar.gz && tar xzf /tmp/app.tar.gz -C /app/ && rm /tmp/app.tar.gz", rule: "Use COPY over ADD, explicit downloads", severity: "low", reason: "ADD has implicit behaviors (URL fetching, tar extraction) that can be surprising." },
  { id: "DF-013", bad: "# No .dockerignore", good: ".git\nnode_modules\n.env\n*.log\nDockerfile\ndocker-compose.yml\n.dockerignore\ntests/\ndocs/\n*.md", rule: "Use .dockerignore", severity: "medium", reason: "Without .dockerignore, secrets, git history, and unnecessary files are included in the build context." },
  { id: "DF-014", bad: "FROM node:18", good: "FROM node:18-alpine", rule: "Use minimal base images", severity: "medium", reason: "Alpine or distroless images have fewer packages, smaller attack surface, and smaller image size." },
  { id: "DF-015", bad: "RUN npm install\nRUN npm run build", good: "RUN npm ci --only=production", rule: "Use deterministic installs", severity: "medium", reason: "npm ci uses the lockfile exactly, ensuring reproducible builds. --only=production skips devDependencies." }
];

export const CONTAINER_ESCAPE_TECHNIQUES = [
  { id: "CE-001", name: "Privileged container", description: "A container running with --privileged flag has all Linux capabilities, can access host devices, and can mount the host filesystem.", prerequisites: ["Container must be running in privileged mode"], steps: ["mount /dev/sda1 /mnt # mount host filesystem", "chroot /mnt # chroot to host", "nsenter -t 1 -m -u -i -n -p -- /bin/bash # enter host namespaces"], detection: "Check for SYS_ADMIN capability or privileged: true in pod spec", mitigation: "Never use --privileged. Grant only specific capabilities needed." },
  { id: "CE-002", name: "Docker socket mount", description: "If the Docker socket (/var/run/docker.sock) is mounted into a container, the container can control the Docker daemon and escape.", prerequisites: ["Docker socket mounted as volume"], steps: ["docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host"], detection: "Check for /var/run/docker.sock in volume mounts", mitigation: "Never mount the Docker socket. Use Docker-in-Docker or Kaniko for building images." },
  { id: "CE-003", name: "SYS_ADMIN + cgroup escape", description: "With SYS_ADMIN capability, mount a cgroup, set release_agent to a host-side script, and trigger it.", prerequisites: ["SYS_ADMIN capability", "cgroup v1"], steps: ["mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp", "echo 1 > /tmp/cgrp/notify_on_release", "echo '/cmd' > /tmp/cgrp/release_agent", "echo '#!/bin/sh' > /cmd && echo 'cat /etc/shadow > /tmp/output' >> /cmd", "chmod +x /cmd && echo $$ > /tmp/cgrp/cgroup.procs"], detection: "Check for SYS_ADMIN capability", mitigation: "Drop all capabilities. Use seccomp profiles." },
  { id: "CE-004", name: "Host PID namespace", description: "With hostPID: true, the container can see all host processes and potentially interact with them.", prerequisites: ["hostPID enabled"], steps: ["ps aux # see host processes", "nsenter -t 1 -m -u -i -n -p -- /bin/bash # enter host namespaces (requires SYS_PTRACE)"], detection: "Check for hostPID: true in pod spec", mitigation: "Never enable hostPID. Use dedicated monitoring containers if needed." },
  { id: "CE-005", name: "Host network namespace", description: "With hostNetwork: true, the container shares the host's network stack, accessing all host network interfaces and services.", prerequisites: ["hostNetwork enabled"], steps: ["Access services bound to localhost on the host", "Sniff host network traffic", "Access metadata services directly"], detection: "Check for hostNetwork: true in pod spec", mitigation: "Never enable hostNetwork unless absolutely required." },
  { id: "CE-006", name: "Writable hostPath volume", description: "A hostPath volume mounting host directories (especially /) gives the container direct access to the host filesystem.", prerequisites: ["hostPath volume with write access"], steps: ["Write to host filesystem via mounted path", "Modify /etc/crontab or /etc/passwd on host", "Plant SSH keys or backdoors"], detection: "Check for hostPath volumes in pod spec", mitigation: "Avoid hostPath volumes. Use PersistentVolumeClaims instead." },
  { id: "CE-007", name: "Kernel exploit", description: "Exploit a kernel vulnerability from within the container to gain code execution on the host.", prerequisites: ["Vulnerable kernel version", "Ability to run exploit code"], examples: ["CVE-2022-0847 (Dirty Pipe)", "CVE-2022-0185 (heap overflow in filesystem context)", "CVE-2021-22555 (Netfilter heap OOB write)", "CVE-2020-14386 (AF_PACKET)"], detection: "Use runtime security tools (Falco, Sysdig) to detect anomalous syscalls", mitigation: "Keep kernel updated. Use seccomp and AppArmor. Run containers with minimal capabilities." },
  { id: "CE-008", name: "CVE-2019-5736 (runc)", description: "Overwrite the runc binary on the host by exploiting a file descriptor leak during container exec.", prerequisites: ["Vulnerable runc version (< 1.0.0-rc6)"], detection: "Check runc version", mitigation: "Update runc to latest version." },
  { id: "CE-009", name: "Leaked service account token", description: "In Kubernetes, default service account tokens mounted at /var/run/secrets can be used to interact with the API server.", prerequisites: ["Service account token mounted (default behavior)"], steps: ["cat /var/run/secrets/kubernetes.io/serviceaccount/token", "curl -k -H 'Authorization: Bearer TOKEN' https://kubernetes.default/api/v1/namespaces"], detection: "Check for automountServiceAccountToken: true", mitigation: "Set automountServiceAccountToken: false on pods that don't need it." },
  { id: "CE-010", name: "CAP_SYS_PTRACE + process injection", description: "With SYS_PTRACE capability and hostPID, inject code into host processes via ptrace.", prerequisites: ["SYS_PTRACE capability", "hostPID: true"], steps: ["Find a host process PID", "Use ptrace to inject shellcode", "Execute in host context"], detection: "Monitor ptrace syscalls with Falco", mitigation: "Drop SYS_PTRACE capability. Disable hostPID." }
];

export const KUBERNETES_RBAC = {
  description: "Kubernetes RBAC controls who can perform what actions on which resources in the cluster.",
  dangerous_permissions: [
    { verbs: ["create"], resources: ["pods"], risk: "critical", reason: "Can create privileged pods, mount host filesystem, or run with hostPID/hostNetwork to escape to the node." },
    { verbs: ["create"], resources: ["pods/exec"], risk: "critical", reason: "Can execute commands inside any running pod, accessing secrets and service account tokens." },
    { verbs: ["get"], resources: ["secrets"], risk: "high", reason: "Can read all secrets in the namespace, including service account tokens, TLS certs, and credentials." },
    { verbs: ["create"], resources: ["serviceaccounts/token"], risk: "critical", reason: "Can generate tokens for any service account, potentially with cluster-admin privileges." },
    { verbs: ["impersonate"], resources: ["users", "groups", "serviceaccounts"], risk: "critical", reason: "Can impersonate any identity, including cluster-admin." },
    { verbs: ["escalate"], resources: ["clusterroles", "roles"], risk: "critical", reason: "Can grant themselves permissions they don't currently have." },
    { verbs: ["bind"], resources: ["clusterroles", "roles"], risk: "critical", reason: "Can bind any role to themselves, including cluster-admin." },
    { verbs: ["create"], resources: ["clusterrolebindings", "rolebindings"], risk: "critical", reason: "Can create bindings granting any role to any subject." },
    { verbs: ["patch", "update"], resources: ["daemonsets", "deployments", "replicasets", "statefulsets"], risk: "high", reason: "Can modify workload specs to inject containers, change images, or add privileged settings." },
    { verbs: ["create"], resources: ["nodes/proxy"], risk: "critical", reason: "Can proxy to the kubelet API on any node, executing commands on pods." },
    { verbs: ["get", "list"], resources: ["nodes/proxy"], risk: "high", reason: "Can read pod logs and exec into pods via kubelet API, bypassing RBAC." }
  ],
  pod_security_standards: [
    { level: "Privileged", description: "No restrictions. For system-level workloads that need full host access.", settings: "All settings allowed" },
    { level: "Baseline", description: "Minimal restrictions to prevent known privilege escalations.", restrictions: ["No privileged containers", "No hostPID/hostIPC/hostNetwork", "No hostPath volumes (except specific paths)", "Limited capabilities (no SYS_ADMIN)", "No /proc mount types except Default", "Seccomp: RuntimeDefault or Localhost"] },
    { level: "Restricted", description: "Heavily restricted, following security best practices.", restrictions: ["All Baseline restrictions", "Must run as non-root (runAsNonRoot: true)", "Must drop ALL capabilities", "Only allowed to add NET_BIND_SERVICE", "Seccomp profile required", "No privilege escalation (allowPrivilegeEscalation: false)", "Volume types: configMap, downwardAPI, emptyDir, persistentVolumeClaim, projected, secret"] }
  ],
  audit_commands: [
    "kubectl auth can-i --list # what can current user do",
    "kubectl auth can-i --list --as=system:serviceaccount:NAMESPACE:SA_NAME # what can a SA do",
    "kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects[]?.name==\"system:anonymous\")'",
    "kubectl get rolebindings,clusterrolebindings --all-namespaces -o json | jq '.items[] | select(.roleRef.name==\"cluster-admin\")'",
    "kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.name'",
    "kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.hostNetwork==true) | .metadata.name'"
  ]
};

export const KUBERNETES_NETWORK_POLICIES = [
  {
    name: "Default deny all ingress",
    description: "Block all incoming traffic to pods in a namespace by default. Explicitly allow only required communication.",
    yaml: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress`
  },
  {
    name: "Default deny all egress",
    description: "Block all outgoing traffic from pods. Essential for preventing data exfiltration and C2 communication.",
    yaml: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress`
  },
  {
    name: "Allow DNS egress",
    description: "After default deny egress, allow DNS resolution (required for most workloads).",
    yaml: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53`
  },
  {
    name: "Allow frontend to backend",
    description: "Allow frontend pods to communicate with backend pods on port 8080.",
    yaml: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: backend
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: frontend
    ports:
    - protocol: TCP
      port: 8080`
  },
  {
    name: "Allow monitoring namespace",
    description: "Allow Prometheus scraping from the monitoring namespace.",
    yaml: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-monitoring
  namespace: production
spec:
  podSelector: {}
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          purpose: monitoring
    ports:
    - protocol: TCP
      port: 9090`
  }
];

export const FALCO_RULES = [
  { name: "Terminal shell in container", description: "Detect when a shell is spawned inside a container, indicating potential compromise or unauthorized access.", condition: "container and proc.name in (bash, sh, zsh, dash, csh) and evt.type=execve and not proc.pname in (crond, sshd, supervisord)" },
  { name: "Write below /etc", description: "Detect file modifications under /etc, which could indicate persistence or configuration tampering.", condition: "container and fd.name startswith /etc and evt.type in (open, openat) and evt.arg.flags contains O_WRONLY" },
  { name: "Read sensitive file", description: "Detect reads of sensitive files like /etc/shadow, /etc/passwd, or credential files.", condition: "container and fd.name in (/etc/shadow, /etc/sudoers, /root/.ssh/authorized_keys, /root/.bash_history) and evt.type=open" },
  { name: "Outbound connection to unusual port", description: "Detect containers making outbound connections to non-standard ports, potentially C2 traffic.", condition: "container and evt.type=connect and fd.type=ipv4 and not fd.sport in (80, 443, 53, 8080, 8443, 3306, 5432, 6379, 27017)" },
  { name: "Container drift detected", description: "Detect new executables being created or downloaded inside a running container.", condition: "container and evt.type in (open, openat) and evt.arg.flags contains O_CREAT and fd.name contains /tmp" },
  { name: "Privileged container started", description: "Alert when a container starts with privileged flag.", condition: "evt.type=container and container.privileged=true" },
  { name: "Namespace change attempted", description: "Detect attempts to change Linux namespaces, which may indicate container escape attempts.", condition: "evt.type in (setns, unshare) and container" },
  { name: "Crypto mining binary detected", description: "Detect common cryptocurrency mining binaries.", condition: "container and proc.name in (xmrig, minerd, minergate, cpuminer, stratum+tcp)" },
  { name: "Mount attempted in container", description: "Detect mount syscalls inside containers, which could be part of escape techniques.", condition: "container and evt.type=mount" },
  { name: "Bulk data read", description: "Detect large reads from databases or filesystems that may indicate data exfiltration.", condition: "container and evt.type=read and evt.rawres > 1048576 and fd.type=file" },
  { name: "kubectl exec detected", description: "Detect kubectl exec sessions into pods.", condition: "container and proc.name=runc and evt.type=execve and proc.args contains exec" },
  { name: "Service account token accessed", description: "Detect reads of Kubernetes service account tokens.", condition: "container and fd.name startswith /var/run/secrets/kubernetes.io and evt.type=open" },
  { name: "Reverse shell detected", description: "Detect common reverse shell patterns (bash -i, nc -e, python -c).", condition: "container and proc.name in (bash, sh, python, python3, perl, ruby, nc, ncat) and proc.args contains '/dev/tcp' or proc.args contains 'socket'" },
  { name: "Symlink created to sensitive path", description: "Detect symlinks pointing to sensitive host paths, a common escape technique.", condition: "container and evt.type=symlink and evt.arg.target startswith /proc" },
  { name: "DNS resolution of suspicious domain", description: "Detect DNS lookups for known malicious TLDs or patterns.", condition: "container and evt.type=connect and fd.type=ipv4 and fd.sport=53" }
];

export const CONTAINER_SCANNING_TOOLS = [
  { name: "Trivy", description: "Comprehensive vulnerability scanner for container images, filesystems, git repos, and Kubernetes. Detects OS and application vulnerabilities, misconfigurations, and secrets.", usage: "trivy image myapp:latest", features: ["CVE scanning", "Misconfiguration detection", "Secret scanning", "SBOM generation", "License scanning"] },
  { name: "Grype", description: "Vulnerability scanner for container images and filesystems by Anchore. Fast scanning with multiple database sources.", usage: "grype myapp:latest", features: ["CVE scanning", "SBOM-based scanning", "Multiple database sources", "CI/CD integration"] },
  { name: "Syft", description: "SBOM (Software Bill of Materials) generator for container images. Creates CycloneDX or SPDX format SBOMs.", usage: "syft myapp:latest -o cyclonedx-json > sbom.json", features: ["Multi-format SBOM output", "Package detection for 20+ ecosystems", "OCI image support"] },
  { name: "Cosign", description: "Container image signing and verification from the Sigstore project. Ensures image integrity and provenance.", usage: "cosign sign --key cosign.key myregistry.io/myapp:latest", features: ["Keyless signing via OIDC", "Transparency log (Rekor)", "In-toto attestations", "Policy enforcement"] },
  { name: "Falco", description: "Runtime security tool for detecting anomalous behavior in containers and Kubernetes at the kernel level.", usage: "falco -c /etc/falco/falco.yaml", features: ["Kernel-level syscall monitoring", "Custom rule language", "Plugin system", "Kubernetes audit log analysis"] },
  { name: "kube-bench", description: "Checks Kubernetes cluster against CIS Kubernetes Benchmark security recommendations.", usage: "kube-bench run --targets master,node", features: ["CIS benchmark checks", "Remediation guidance", "JSON output for automation"] },
  { name: "kubeaudit", description: "Audits Kubernetes clusters for security concerns. Checks for common misconfigurations.", usage: "kubeaudit all -f deployment.yaml", features: ["Image scanning", "RBAC analysis", "Network policy checks", "Resource limit checks"] },
  { name: "Polaris", description: "Validates Kubernetes configuration against best practices. Runs as CLI, webhook, or dashboard.", usage: "polaris audit --format=json", features: ["Pod security checks", "Resource management", "Networking", "Custom checks"] }
];
