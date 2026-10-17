// Docker and Kubernetes security analysis tool
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const DOCKERFILE_CHECKS = [
  { id: "root-user", severity: "high", test: function(lines) { var hasUser = lines.some(function(l) { return /^USER\s/i.test(l.trim()); }); return !hasUser ? "No USER directive found -- container runs as root by default" : null; } },
  { id: "latest-tag", severity: "medium", test: function(lines) { return lines.filter(function(l) { return /^FROM\s/i.test(l.trim()); }).some(function(l) { return /:latest\s*$/i.test(l.trim()) || (!/:/i.test(l.trim().split(/\s+/)[1] || "") && !/@sha256:/i.test(l.trim())); }) ? "Base image uses :latest tag or no tag (unpinned version)" : null; } },
  { id: "no-healthcheck", severity: "low", test: function(lines) { return !lines.some(function(l) { return /^HEALTHCHECK\s/i.test(l.trim()); }) ? "No HEALTHCHECK instruction (orchestrator cannot detect unhealthy containers)" : null; } },
  { id: "add-instead-copy", severity: "medium", test: function(lines) { return lines.some(function(l) { var t = l.trim(); return /^ADD\s/i.test(t) && !/(\.tar|\.gz|\.bz2|\.xz)/i.test(t); }) ? "Using ADD instead of COPY for non-archive files (ADD can fetch remote URLs)" : null; } },
  { id: "hardcoded-secrets", severity: "critical", test: function(lines) { var patterns = [/password\s*=\s*["'][^"']+["']/i, /api_key\s*=\s*["'][^"']+["']/i, /secret\s*=\s*["'][^"']+["']/i, /token\s*=\s*["'][^"']+["']/i, /AWS_ACCESS_KEY/i, /PRIVATE.KEY/i]; return lines.some(function(l) { return patterns.some(function(p) { return p.test(l); }); }) ? "Possible hardcoded secrets/credentials in Dockerfile" : null; } },
  { id: "expose-sensitive", severity: "medium", test: function(lines) { var sensitive = ["22","23","3389","5432","3306","1433","6379","27017","9200","2375","2376","10250"]; return lines.filter(function(l) { return /^EXPOSE\s/i.test(l.trim()); }).some(function(l) { return sensitive.some(function(p) { return l.includes(p); }); }) ? "Exposing potentially sensitive ports (SSH, DB, Docker API, Kubelet)" : null; } },
  { id: "pip-no-cache", severity: "low", test: function(lines) { return lines.some(function(l) { return /pip\s+install/i.test(l) && !(/--no-cache-dir/i.test(l)); }) ? "pip install without --no-cache-dir (larger image, cached packages)" : null; } },
  { id: "apt-no-recommends", severity: "low", test: function(lines) { return lines.some(function(l) { return /apt-get\s+install/i.test(l) && !(/--no-install-recommends/i.test(l)); }) ? "apt-get install without --no-install-recommends (installs unnecessary packages)" : null; } },
  { id: "apt-no-clean", severity: "low", test: function(lines) { var hasInstall = lines.some(function(l) { return /apt-get\s+install/i.test(l); }); var hasClean = lines.some(function(l) { return /apt-get\s+clean/i.test(l) || /rm\s+-rf\s+\/var\/lib\/apt/i.test(l); }); return hasInstall && !hasClean ? "apt-get install without cleanup (rm -rf /var/lib/apt/lists/*)" : null; } },
  { id: "copy-all", severity: "medium", test: function(lines) { return lines.some(function(l) { return /^COPY\s+\.\s+\./i.test(l.trim()) || /^COPY\s+\.\s+\//i.test(l.trim()); }) ? "COPY . . copies entire build context (may include .git, .env, secrets)" : null; } },
  { id: "no-multistage", severity: "low", test: function(lines) { var fromCount = lines.filter(function(l) { return /^FROM\s/i.test(l.trim()); }).length; return fromCount === 1 ? "Single-stage build (multi-stage reduces final image size and attack surface)" : null; } },
  { id: "env-secrets", severity: "high", test: function(lines) { return lines.some(function(l) { return /^ENV\s/i.test(l.trim()) && /(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)/i.test(l); }) ? "Sensitive values set via ENV (visible in image history and inspect)" : null; } },
  { id: "curl-bash", severity: "high", test: function(lines) { return lines.some(function(l) { return /curl.*\|\s*(ba)?sh/i.test(l) || /wget.*\|\s*(ba)?sh/i.test(l); }) ? "Piping curl/wget to shell (unverified remote code execution)" : null; } },
  { id: "sudo-installed", severity: "medium", test: function(lines) { return lines.some(function(l) { return /install.*\bsudo\b/i.test(l); }) ? "sudo is installed in container (unnecessary, use USER directive instead)" : null; } },
  { id: "chmod-777", severity: "high", test: function(lines) { return lines.some(function(l) { return /chmod\s+777/i.test(l); }) ? "chmod 777 grants world-writable permissions (security risk)" : null; } },
];

const K8S_CHECKS = [
  { id: "privileged", severity: "critical", test: function(y) { return /privileged:\s*true/i.test(y) ? "Container runs in privileged mode (full host access)" : null; } },
  { id: "host-network", severity: "high", test: function(y) { return /hostNetwork:\s*true/i.test(y) ? "Pod uses host network namespace" : null; } },
  { id: "host-pid", severity: "high", test: function(y) { return /hostPID:\s*true/i.test(y) ? "Pod uses host PID namespace (can see/signal host processes)" : null; } },
  { id: "host-ipc", severity: "high", test: function(y) { return /hostIPC:\s*true/i.test(y) ? "Pod uses host IPC namespace" : null; } },
  { id: "run-as-root", severity: "high", test: function(y) { return /runAsUser:\s*0\b/i.test(y) ? "Container explicitly runs as root (UID 0)" : null; } },
  { id: "no-run-as-nonroot", severity: "medium", test: function(y) { return !(/runAsNonRoot:\s*true/i.test(y)) ? "runAsNonRoot not set to true (container may run as root)" : null; } },
  { id: "no-readonly-rootfs", severity: "medium", test: function(y) { return !(/readOnlyRootFilesystem:\s*true/i.test(y)) ? "readOnlyRootFilesystem not enabled (container can write to filesystem)" : null; } },
  { id: "dangerous-caps", severity: "critical", test: function(y) { var caps = ["SYS_ADMIN","NET_ADMIN","SYS_PTRACE","SYS_MODULE","DAC_OVERRIDE","NET_RAW","SYS_RAWIO","SYS_CHROOT","MKNOD","AUDIT_WRITE","SETUID","SETGID"]; var found = []; caps.forEach(function(c) { if (new RegExp("\\b" + c + "\\b").test(y)) found.push(c); }); return found.length ? "Dangerous capabilities added: " + found.join(", ") : null; } },
  { id: "no-drop-all", severity: "medium", test: function(y) { return !(/drop:[\s\S]*?-\s*ALL/i.test(y) || /drop:[\s\S]*?-\s*"ALL"/i.test(y)) ? "Capabilities not dropped (should drop ALL, then add only what's needed)" : null; } },
  { id: "no-resource-limits", severity: "medium", test: function(y) { return !(/limits:/i.test(y)) ? "No resource limits set (container can consume all node resources)" : null; } },
  { id: "no-security-context", severity: "medium", test: function(y) { return !(/securityContext:/i.test(y)) ? "No securityContext defined" : null; } },
  { id: "automount-sa", severity: "medium", test: function(y) { return !(/automountServiceAccountToken:\s*false/i.test(y)) ? "Service account token auto-mounted (default: true, risk of token theft)" : null; } },
  { id: "hostpath-volumes", severity: "high", test: function(y) { return /hostPath:/i.test(y) ? "hostPath volume mounted (direct host filesystem access)" : null; } },
  { id: "image-pull-always", severity: "low", test: function(y) { return /imagePullPolicy:\s*Never/i.test(y) ? "imagePullPolicy set to Never (won't pull security updates)" : null; } },
  { id: "latest-image", severity: "medium", test: function(y) { var m = y.match(/image:\s*["']?([^\s"']+)/gi); return m && m.some(function(i) { return /:latest/i.test(i) || !(/:/.test(i.split("image:")[1] || "")); }) ? "Container image uses :latest tag or no tag (unpinned)" : null; } },
  { id: "allow-priv-escalation", severity: "high", test: function(y) { return /allowPrivilegeEscalation:\s*true/i.test(y) || (!(/allowPrivilegeEscalation:\s*false/i.test(y)) && !(/runAsNonRoot:\s*true/i.test(y))) ? "allowPrivilegeEscalation not explicitly set to false" : null; } },
];

const DOCKER_COMMANDS = [
  { cat: "Images", commands: [
    { cmd: "docker images", desc: "List all local images" },
    { cmd: "docker image inspect <image>", desc: "Show image metadata (layers, env, entrypoint)" },
    { cmd: "docker history <image>", desc: "Show image layer history (commands that built it)" },
    { cmd: "docker image prune -a", desc: "Remove all unused images" },
    { cmd: "docker save <image> -o image.tar", desc: "Export image to tar archive for offline analysis" },
    { cmd: "docker load -i image.tar", desc: "Import image from tar archive" },
    { cmd: "docker trust inspect <image>", desc: "Check Docker Content Trust signatures" },
    { cmd: "docker manifest inspect <image>", desc: "Inspect image manifest (digests, platforms)" },
  ]},
  { cat: "Containers", commands: [
    { cmd: "docker ps -a", desc: "List all containers (running and stopped)" },
    { cmd: "docker inspect <container>", desc: "Show container configuration (mounts, network, env)" },
    { cmd: "docker logs <container>", desc: "View container logs" },
    { cmd: "docker exec -it <container> /bin/sh", desc: "Get shell inside running container" },
    { cmd: "docker cp <container>:/path /local/path", desc: "Copy files out of container" },
    { cmd: "docker diff <container>", desc: "Show filesystem changes made inside container" },
    { cmd: "docker top <container>", desc: "Show running processes inside container" },
    { cmd: "docker stats", desc: "Live resource usage (CPU, memory, network, I/O)" },
    { cmd: "docker export <container> -o container.tar", desc: "Export container filesystem" },
  ]},
  { cat: "Security Scanning", commands: [
    { cmd: "docker scout cves <image>", desc: "Scan image for CVEs with Docker Scout" },
    { cmd: "trivy image <image>", desc: "Scan image for vulnerabilities with Trivy" },
    { cmd: "grype <image>", desc: "Scan image for vulnerabilities with Grype" },
    { cmd: "docker scout recommendations <image>", desc: "Get base image upgrade recommendations" },
    { cmd: "syft <image>", desc: "Generate SBOM (Software Bill of Materials)" },
    { cmd: "docker scan <image>", desc: "Scan image with Snyk (legacy)" },
    { cmd: "dockle <image>", desc: "Lint Dockerfile best practices" },
    { cmd: "hadolint Dockerfile", desc: "Lint Dockerfile for issues" },
  ]},
  { cat: "Network", commands: [
    { cmd: "docker network ls", desc: "List Docker networks" },
    { cmd: "docker network inspect <network>", desc: "Show network config and connected containers" },
    { cmd: "docker network create --internal <name>", desc: "Create isolated network (no external access)" },
    { cmd: "docker run --network=none <image>", desc: "Run container with no network access" },
    { cmd: "docker port <container>", desc: "Show port mappings" },
  ]},
  { cat: "Runtime Security", commands: [
    { cmd: "docker run --read-only <image>", desc: "Run with read-only filesystem" },
    { cmd: "docker run --cap-drop=ALL <image>", desc: "Run with all capabilities dropped" },
    { cmd: "docker run --security-opt=no-new-privileges <image>", desc: "Prevent privilege escalation" },
    { cmd: "docker run --pids-limit=100 <image>", desc: "Limit number of processes (fork bomb protection)" },
    { cmd: 'docker run --memory=256m --cpus=".5" <image>', desc: "Set resource limits" },
    { cmd: "docker run --user 1000:1000 <image>", desc: "Run as non-root user" },
    { cmd: "docker run --tmpfs /tmp:rw,noexec,nosuid <image>", desc: "Mount tmpfs without exec" },
    { cmd: "docker run --security-opt seccomp=profile.json <image>", desc: "Apply seccomp profile" },
    { cmd: "docker run --security-opt apparmor=docker-default <image>", desc: "Apply AppArmor profile" },
  ]},
  { cat: "Docker API", commands: [
    { cmd: "curl --unix-socket /var/run/docker.sock http://localhost/version", desc: "Query Docker daemon via socket" },
    { cmd: "curl --unix-socket /var/run/docker.sock http://localhost/containers/json", desc: "List containers via API" },
    { cmd: "ss -lnp | grep 2375", desc: "Check if Docker TCP API is exposed (insecure)" },
    { cmd: "docker context ls", desc: "List configured Docker contexts" },
  ]},
];

const KUBECTL_COMMANDS = [
  { cat: "Cluster Info", commands: [
    { cmd: "kubectl cluster-info", desc: "Show cluster endpoint and services" },
    { cmd: "kubectl get nodes -o wide", desc: "List nodes with IPs and versions" },
    { cmd: "kubectl api-resources", desc: "List all API resources (RBAC recon)" },
    { cmd: "kubectl auth can-i --list", desc: "List your permissions" },
    { cmd: "kubectl auth can-i create pods", desc: "Check specific permission" },
    { cmd: "kubectl get namespaces", desc: "List all namespaces" },
    { cmd: "kubectl version --short", desc: "Show K8s version (check for CVEs)" },
  ]},
  { cat: "Pod Security", commands: [
    { cmd: "kubectl get pods --all-namespaces -o wide", desc: "List all pods across namespaces" },
    { cmd: "kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name} {.spec.containers[*].securityContext}{\"\\n\"}{end}'", desc: "Show pod security contexts" },
    { cmd: "kubectl describe pod <pod>", desc: "Full pod details (env vars, mounts, events)" },
    { cmd: "kubectl exec -it <pod> -- /bin/sh", desc: "Get shell in pod" },
    { cmd: "kubectl logs <pod> --previous", desc: "View logs from crashed pod" },
    { cmd: "kubectl get pods -o jsonpath='{range .items[*]}{.spec.containers[*].image}{\"\\n\"}{end}'", desc: "List all container images" },
  ]},
  { cat: "RBAC", commands: [
    { cmd: "kubectl get clusterroles", desc: "List cluster-wide roles" },
    { cmd: "kubectl get clusterrolebindings", desc: "List cluster-wide role bindings" },
    { cmd: "kubectl get roles -A", desc: "List namespaced roles" },
    { cmd: "kubectl get rolebindings -A", desc: "List namespaced role bindings" },
    { cmd: "kubectl describe clusterrole cluster-admin", desc: "Show cluster-admin permissions" },
    { cmd: "kubectl auth can-i --list --as=system:serviceaccount:default:default", desc: "Check default SA permissions" },
  ]},
  { cat: "Secrets", commands: [
    { cmd: "kubectl get secrets -A", desc: "List all secrets across namespaces" },
    { cmd: "kubectl get secret <name> -o jsonpath='{.data}'", desc: "Show secret data (base64)" },
    { cmd: "kubectl get secret <name> -o jsonpath='{.data.password}' | base64 -d", desc: "Decode secret value" },
    { cmd: "kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.volumes[*].secret.secretName}{\"\\n\"}{end}'", desc: "Show which pods mount which secrets" },
  ]},
  { cat: "Network Policies", commands: [
    { cmd: "kubectl get networkpolicies -A", desc: "List all network policies" },
    { cmd: "kubectl describe networkpolicy <name>", desc: "Show policy details (ingress/egress rules)" },
    { cmd: "kubectl get services -A", desc: "List all services" },
    { cmd: "kubectl get ingress -A", desc: "List all ingress resources" },
  ]},
];

const CONTAINER_ESCAPES = [
  { name: "Docker Socket Mount", desc: "If /var/run/docker.sock is mounted in the container, you can control the Docker daemon and create privileged containers on the host.", detection: "Check mounts: mount | grep docker.sock", severity: "critical" },
  { name: "Privileged Container", desc: "A container running with --privileged has full access to host devices. Can mount host filesystem, load kernel modules, access all devices.", detection: "Check: cat /proc/1/status | grep CapEff (should show all capabilities)", severity: "critical" },
  { name: "SYS_ADMIN Capability", desc: "SYS_ADMIN allows mounting filesystems. Can mount host disk: mount /dev/sda1 /mnt", detection: "capsh --print | grep sys_admin", severity: "critical" },
  { name: "SYS_PTRACE Capability", desc: "Allows process injection via ptrace. Can inject code into host processes visible via /proc.", detection: "capsh --print | grep sys_ptrace", severity: "high" },
  { name: "Host PID Namespace", desc: "With hostPID: true, container sees all host processes. Combined with SYS_PTRACE enables process injection.", detection: "ps aux shows host processes", severity: "high" },
  { name: "Writable hostPath Volume", desc: "If a hostPath volume is writable, can write cron jobs, authorized_keys, or overwrite binaries on the host.", detection: "mount | grep -v overlay | grep rw", severity: "critical" },
  { name: "CVE-2024-21626 (Leaky Vessels)", desc: "runc vulnerability allowing container escape via /proc/self/fd race condition. Affects runc < 1.1.12.", detection: "runc --version", severity: "critical" },
  { name: "CVE-2022-0185 (Filesystem Context)", desc: "Linux kernel bug in legacy filesystem context handling allows unprivileged user to escalate to root and escape container.", detection: "uname -r (affected: < 5.16.2)", severity: "critical" },
  { name: "CVE-2022-0492 (cgroups v1)", desc: "cgroups v1 release_agent allows container escape when container has CAP_SYS_ADMIN or runs without user namespace.", detection: "cat /proc/self/cgroup", severity: "high" },
  { name: "Kernel Exploit", desc: "Kernel vulnerabilities (DirtyPipe, DirtyCow) can be exploited from within containers to escape. Container shares kernel with host.", detection: "uname -r (check against known CVEs)", severity: "critical" },
  { name: "Exposed Kubelet API", desc: "If kubelet API (port 10250) is accessible without auth, can execute commands in any pod on the node.", detection: "curl -sk https://<node-ip>:10250/pods", severity: "critical" },
  { name: "Service Account Token", desc: "Default SA token mounted at /var/run/secrets/kubernetes.io/serviceaccount/token. If SA has excessive RBAC, can escalate in cluster.", detection: "cat /var/run/secrets/kubernetes.io/serviceaccount/token", severity: "high" },
  { name: "Environment Variable Secrets", desc: "Secrets passed as env vars are visible in /proc/*/environ, container inspect, and logs. Can leak to monitoring.", detection: "cat /proc/1/environ | tr '\\0' '\\n'", severity: "medium" },
  { name: "CoreDNS/kube-dns Poisoning", desc: "If attacker controls a pod, can attempt DNS spoofing within the cluster to redirect traffic.", detection: "nslookup kubernetes.default.svc.cluster.local", severity: "medium" },
];

const CIS_DOCKER = [
  { id: "1.1", text: "Ensure a separate partition for containers has been created", level: 1 },
  { id: "1.2", text: "Ensure only trusted users are allowed to control Docker daemon", level: 1 },
  { id: "1.3", text: "Ensure auditing is configured for Docker daemon", level: 1 },
  { id: "2.1", text: "Run the Docker daemon as a non-root user (rootless mode)", level: 2 },
  { id: "2.2", text: "Ensure network traffic is restricted between containers", level: 1 },
  { id: "2.3", text: "Ensure the logging level is set to 'info'", level: 1 },
  { id: "2.4", text: "Ensure Docker is allowed to make changes to iptables", level: 1 },
  { id: "2.5", text: "Ensure insecure registries are not used", level: 1 },
  { id: "2.6", text: "Ensure aufs storage driver is not used", level: 1 },
  { id: "2.7", text: "Ensure TLS authentication for Docker daemon is configured", level: 1 },
  { id: "2.8", text: "Ensure the default ulimit is configured appropriately", level: 1 },
  { id: "2.9", text: "Enable user namespace support", level: 2 },
  { id: "2.10", text: "Ensure the default cgroup usage has been confirmed", level: 2 },
  { id: "2.11", text: "Ensure base device size is not changed until needed", level: 2 },
  { id: "2.12", text: "Ensure that authorization for Docker client commands is enabled", level: 2 },
  { id: "2.13", text: "Ensure centralized and remote logging is configured", level: 2 },
  { id: "2.14", text: "Ensure containers are restricted from acquiring new privileges", level: 1 },
  { id: "2.15", text: "Ensure live restore is enabled", level: 1 },
  { id: "2.16", text: "Ensure Userland Proxy is disabled", level: 2 },
  { id: "2.17", text: "Ensure that a daemon-wide custom seccomp profile is applied", level: 2 },
  { id: "3.1", text: "Ensure docker.service file ownership is set to root:root", level: 1 },
  { id: "3.2", text: "Ensure docker.service file permissions are set to 644 or more restrictive", level: 1 },
  { id: "3.3", text: "Ensure docker.socket file ownership is set to root:root", level: 1 },
  { id: "3.4", text: "Ensure docker.socket file permissions are set to 644 or more restrictive", level: 1 },
  { id: "4.1", text: "Ensure that a user for the container has been created", level: 1 },
  { id: "4.2", text: "Ensure that containers use only trusted base images", level: 1 },
  { id: "4.3", text: "Ensure that unnecessary packages are not installed", level: 1 },
  { id: "4.4", text: "Ensure images are scanned for vulnerabilities", level: 1 },
  { id: "4.5", text: "Ensure Content trust for Docker is enabled", level: 2 },
  { id: "4.6", text: "Ensure that HEALTHCHECK instructions have been added", level: 1 },
  { id: "5.1", text: "Ensure that AppArmor profile is enabled", level: 1 },
  { id: "5.2", text: "Ensure SELinux security options are set", level: 2 },
  { id: "5.3", text: "Ensure that Linux kernel capabilities are restricted", level: 1 },
  { id: "5.4", text: "Ensure that privileged containers are not used", level: 1 },
  { id: "5.5", text: "Ensure sensitive host system directories are not mounted", level: 1 },
  { id: "5.6", text: "Ensure sshd is not running within containers", level: 1 },
  { id: "5.7", text: "Ensure privileged ports are not mapped within containers", level: 1 },
  { id: "5.8", text: "Ensure that only needed ports are open on the container", level: 1 },
  { id: "5.9", text: "Ensure the host's network namespace is not shared", level: 1 },
  { id: "5.10", text: "Ensure memory usage for containers is limited", level: 1 },
  { id: "5.11", text: "Ensure that CPU priority is set appropriately", level: 1 },
  { id: "5.12", text: "Ensure the container's root filesystem is mounted as read-only", level: 1 },
  { id: "5.13", text: "Ensure that incoming container traffic is bound to a specific host interface", level: 1 },
  { id: "5.14", text: "Ensure 'on-failure' container restart policy is set to '5'", level: 1 },
  { id: "5.15", text: "Ensure the host's process namespace is not shared", level: 1 },
  { id: "5.16", text: "Ensure the host's IPC namespace is not shared", level: 1 },
  { id: "5.17", text: "Ensure that host devices are not directly exposed to containers", level: 1 },
  { id: "5.18", text: "Ensure that the default ulimit is overwritten at runtime if needed", level: 1 },
  { id: "5.19", text: "Ensure mount propagation mode is not set to shared", level: 1 },
  { id: "5.20", text: "Ensure the host's UTS namespace is not shared", level: 1 },
  { id: "5.21", text: "Ensure the default seccomp profile is not disabled", level: 1 },
  { id: "5.22", text: "Ensure that docker exec commands are not used with the privileged option", level: 2 },
  { id: "5.23", text: "Ensure that docker exec commands are not used with the user=root option", level: 2 },
  { id: "5.24", text: "Ensure that cgroup usage is confirmed", level: 1 },
  { id: "5.25", text: "Ensure that the container is restricted from acquiring additional privileges", level: 1 },
  { id: "5.26", text: "Ensure that container health is checked at runtime", level: 1 },
  { id: "5.27", text: "Ensure that Docker commands always make use of the latest version of their image", level: 1 },
  { id: "5.28", text: "Ensure that the PIDs cgroup limit is used", level: 1 },
];

function renderDockerfileTab(container) {
  container.innerHTML =
    '<h2 class="pg-h2">Dockerfile Security Analyzer</h2>' +
    '<p class="muted">Paste a Dockerfile below to check for security issues and best practices.</p>' +
    '<textarea class="tk-in" id="cs-docker-input" rows="12" placeholder="FROM ubuntu:latest\nRUN apt-get update && apt-get install -y curl\nCOPY . .\nCMD [\"app\"]"></textarea>' +
    '<div class="tk-btns"><button class="btn sm" id="cs-docker-analyze">Analyze Dockerfile</button></div>' +
    '<div id="cs-docker-out"></div>';

  container.querySelector("#cs-docker-analyze").onclick = function() {
    var input = container.querySelector("#cs-docker-input").value.trim();
    if (!input) return;
    var lines = input.split(/\r?\n/);
    var findings = [];
    DOCKERFILE_CHECKS.forEach(function(check) {
      var result = check.test(lines);
      if (result) findings.push({ id: check.id, severity: check.severity, msg: result });
    });
    var severityColors = { critical: "#ef4444", high: "#f97316", medium: "#f59e0b", low: "#3b82f6" };
    var html = '<div style="margin-top:12px"><div style="font-size:1.05rem;font-weight:600;margin-bottom:8px">' + findings.length + ' issue(s) found</div>';
    if (findings.length === 0) html += '<div style="color:#22c55e;padding:12px;background:var(--card);border-radius:6px">No issues detected. Good job!</div>';
    findings.forEach(function(f) {
      html += '<div style="display:flex;gap:8px;align-items:flex-start;padding:8px 12px;margin:4px 0;border-left:3px solid ' + (severityColors[f.severity] || "#888") + ';background:var(--card);border-radius:0 4px 4px 0">' +
        '<span style="font-size:.7rem;font-weight:700;text-transform:uppercase;min-width:60px;color:' + (severityColors[f.severity] || "#888") + '">' + esc(f.severity) + '</span>' +
        '<span style="font-size:.85rem">' + esc(f.msg) + '</span></div>';
    });
    html += '</div>';
    container.querySelector("#cs-docker-out").innerHTML = html;
  };
}

function renderK8sTab(container) {
  container.innerHTML =
    '<h2 class="pg-h2">Kubernetes Manifest Analyzer</h2>' +
    '<p class="muted">Paste a Kubernetes pod/deployment YAML to check pod security.</p>' +
    '<textarea class="tk-in" id="cs-k8s-input" rows="12" placeholder="apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\nspec:\n  containers:\n  - name: app\n    image: nginx:latest"></textarea>' +
    '<div class="tk-btns"><button class="btn sm" id="cs-k8s-analyze">Analyze Manifest</button></div>' +
    '<div id="cs-k8s-out"></div>';

  container.querySelector("#cs-k8s-analyze").onclick = function() {
    var input = container.querySelector("#cs-k8s-input").value.trim();
    if (!input) return;
    var findings = [];
    K8S_CHECKS.forEach(function(check) {
      var result = check.test(input);
      if (result) findings.push({ id: check.id, severity: check.severity, msg: result });
    });
    var severityColors = { critical: "#ef4444", high: "#f97316", medium: "#f59e0b", low: "#3b82f6" };
    var html = '<div style="margin-top:12px"><div style="font-size:1.05rem;font-weight:600;margin-bottom:8px">' + findings.length + ' issue(s) found</div>';
    if (findings.length === 0) html += '<div style="color:#22c55e;padding:12px;background:var(--card);border-radius:6px">No issues detected.</div>';
    findings.forEach(function(f) {
      html += '<div style="display:flex;gap:8px;align-items:flex-start;padding:8px 12px;margin:4px 0;border-left:3px solid ' + (severityColors[f.severity] || "#888") + ';background:var(--card);border-radius:0 4px 4px 0">' +
        '<span style="font-size:.7rem;font-weight:700;text-transform:uppercase;min-width:60px;color:' + (severityColors[f.severity] || "#888") + '">' + esc(f.severity) + '</span>' +
        '<span style="font-size:.85rem">' + esc(f.msg) + '</span></div>';
    });
    html += '</div>';
    container.querySelector("#cs-k8s-out").innerHTML = html;
  };
}

function renderCommandRefTab(container, title, commands) {
  var html = '<h2 class="pg-h2">' + esc(title) + '</h2>';
  commands.forEach(function(cat) {
    html += '<h3 style="margin:16px 0 6px;font-size:.9rem;color:var(--acc)">' + esc(cat.cat) + '</h3>';
    html += '<div style="display:grid;gap:4px">';
    cat.commands.forEach(function(c) {
      html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:6px 10px;background:var(--card);border-radius:4px;font-size:.82rem">' +
        '<code style="color:var(--acc);word-break:break-all">' + esc(c.cmd) + '</code>' +
        '<span class="muted">' + esc(c.desc) + '</span></div>';
    });
    html += '</div>';
  });
  container.innerHTML = html;
}

function renderEscapesTab(container) {
  var html = '<h2 class="pg-h2">Container Escape Techniques</h2>' +
    '<p class="muted">Known techniques for escaping container isolation. Understanding these helps build better defenses.</p>';
  CONTAINER_ESCAPES.forEach(function(e) {
    var col = e.severity === "critical" ? "#ef4444" : e.severity === "high" ? "#f97316" : "#f59e0b";
    html += '<div style="background:var(--card);border:1px solid var(--line);border-left:3px solid ' + col + ';border-radius:0 6px 6px 0;padding:12px;margin:8px 0">' +
      '<div style="display:flex;justify-content:space-between;align-items:center">' +
        '<strong style="font-size:.9rem">' + esc(e.name) + '</strong>' +
        '<span style="font-size:.7rem;font-weight:700;text-transform:uppercase;color:' + col + '">' + esc(e.severity) + '</span>' +
      '</div>' +
      '<p style="font-size:.83rem;margin:6px 0">' + esc(e.desc) + '</p>' +
      '<div style="font-size:.78rem;color:var(--acc);font-family:var(--font-mono,monospace)">Detection: ' + esc(e.detection) + '</div>' +
    '</div>';
  });
  container.innerHTML = html;
}

function renderCISTab(container) {
  var html = '<h2 class="pg-h2">CIS Docker Benchmark</h2>' +
    '<p class="muted">' + CIS_DOCKER.length + ' security checks from the CIS Docker Benchmark. Track your compliance status.</p>';
  var saved = {};
  try { saved = JSON.parse(localStorage.getItem("dn_cis_docker") || "{}"); } catch(e) {}
  html += '<div style="display:flex;gap:12px;margin:12px 0"><span style="font-size:.85rem">Completed: <strong id="cs-cis-count">0</strong>/' + CIS_DOCKER.length + '</span></div>';
  html += '<div id="cs-cis-list">';
  CIS_DOCKER.forEach(function(item) {
    var checked = saved[item.id] ? " checked" : "";
    html += '<label style="display:flex;gap:8px;align-items:flex-start;padding:6px 0;border-bottom:1px solid var(--line);font-size:.83rem;cursor:pointer">' +
      '<input type="checkbox" data-cis="' + esc(item.id) + '"' + checked + ' style="margin-top:3px">' +
      '<span><strong>' + esc(item.id) + '</strong> ' + esc(item.text) + ' <span class="muted">(Level ' + item.level + ')</span></span>' +
    '</label>';
  });
  html += '</div>';
  container.innerHTML = html;
  function updateCount() {
    var count = container.querySelectorAll('input[data-cis]:checked').length;
    container.querySelector("#cs-cis-count").textContent = count;
  }
  updateCount();
  container.querySelector("#cs-cis-list").onchange = function(e) {
    var cb = e.target;
    if (cb.dataset.cis) {
      var s = {};
      try { s = JSON.parse(localStorage.getItem("dn_cis_docker") || "{}"); } catch(ex) {}
      if (cb.checked) s[cb.dataset.cis] = true; else delete s[cb.dataset.cis];
      try { localStorage.setItem("dn_cis_docker", JSON.stringify(s)); } catch(ex) {}
      updateCount();
    }
  };
}

const CS_TABS = [
  { id: "dockerfile", label: "Dockerfile Analyzer", render: renderDockerfileTab },
  { id: "k8s", label: "K8s Manifest Analyzer", render: renderK8sTab },
  { id: "docker-cmds", label: "Docker Commands", render: function(c) { renderCommandRefTab(c, "Docker Security Commands", DOCKER_COMMANDS); } },
  { id: "kubectl-cmds", label: "kubectl Commands", render: function(c) { renderCommandRefTab(c, "kubectl Security Commands", KUBECTL_COMMANDS); } },
  { id: "escapes", label: "Container Escapes", render: renderEscapesTab },
  { id: "cis", label: "CIS Benchmark", render: renderCISTab },
];

export function renderContainerSecurity(main) {
  main.innerHTML =
    '<h1 class="pg-h1">Container Security</h1>' +
    '<p class="muted pg-sub">Analyze Dockerfiles and Kubernetes manifests for security issues, reference commands, and track CIS compliance.</p>' +
    '<div class="tab-bar" id="cs-tabs">' +
      CS_TABS.map(function(t, i) { return '<button class="tab' + (i === 0 ? ' active' : '') + '" data-tab="' + t.id + '">' + t.label + '</button>'; }).join('') +
    '</div>' +
    '<div id="cs-content" style="margin-top:12px"></div>';

  var tabBar = main.querySelector('#cs-tabs');
  var content = main.querySelector('#cs-content');
  function switchTab(tabId) {
    tabBar.querySelectorAll('.tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === tabId); });
    var tab = CS_TABS.find(function(t) { return t.id === tabId; });
    if (tab) { content.innerHTML = ''; tab.render(content); }
  }
  tabBar.onclick = function(e) { var btn = e.target.closest('.tab'); if (btn) switchTab(btn.dataset.tab); };
  switchTab('dockerfile');
}
