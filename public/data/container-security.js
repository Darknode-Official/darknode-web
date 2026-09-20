/**
 * =============================================================================
 * Container & Kubernetes Security -- Comprehensive Reference
 * =============================================================================
 *
 * Copyright (c) 2024-2026 Darknode Project
 * All rights reserved.
 *
 * This file provides an exhaustive reference for Docker and Kubernetes
 * security: common misconfigurations, real-world attack techniques,
 * CIS Benchmark-aligned hardening controls, the container security tool
 * ecosystem, Dockerfile best practices, and example Kubernetes
 * NetworkPolicy manifests.
 *
 * Primary sources referenced throughout:
 *   - CIS Docker Benchmark v1.6.0            (cisecurity.org)
 *   - CIS Kubernetes Benchmark v1.8.0        (cisecurity.org)
 *   - NIST SP 800-190 Application Container Security Guide
 *   - Kubernetes official docs               (kubernetes.io/docs/concepts/security)
 *   - MITRE ATT&CK for Containers            (attack.mitre.org)
 *
 * NOTICE: This material is provided for authorized security testing,
 * defensive hardening, and educational purposes only. Always obtain
 * proper authorization before testing systems you do not own.
 *
 * =============================================================================
 */

// =============================================================================
// 1. DOCKER_SECURITY_ISSUES
// =============================================================================

const DOCKER_SECURITY_ISSUES = [

  {
    issue: 'Privileged containers (--privileged)',
    risk:
      'Running a container with --privileged disables nearly all of the kernel isolation ' +
      'mechanisms that make containers a security boundary. The container is granted all ' +
      'Linux capabilities, seccomp and AppArmor/SELinux confinement are disabled, and the ' +
      'container is given direct access to all host devices under /dev.',
    impact:
      'A compromised privileged container can load kernel modules, remount the host ' +
      'filesystem, access host devices (disks, GPUs, USB), and trivially escape to full ' +
      'root access on the underlying host, defeating the purpose of containerization entirely.',
    detection:
      'docker inspect --format "{{.HostConfig.Privileged}}" <container>\n' +
      'docker ps -q | xargs -n1 docker inspect --format "{{.Name}}: Privileged={{.HostConfig.Privileged}}"',
    remediation:
      'Never use --privileged in production. If specific host access is required, grant only ' +
      'the exact capabilities and devices needed:\n' +
      'docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE --device=/dev/snd myimage\n' +
      'In Kubernetes set securityContext.privileged: false and use a restrictive ' +
      'PodSecurity "restricted" profile to block privileged pods cluster-wide.',
    cisReference: 'CIS Docker Benchmark 5.4',
  },

  {
    issue: 'Exposed Docker socket (/var/run/docker.sock)',
    risk:
      'Mounting the host Docker socket into a container (-v /var/run/docker.sock:/var/run/docker.sock) ' +
      'or exposing the Docker daemon over an unauthenticated TCP socket (tcp://0.0.0.0:2375) ' +
      'gives whoever can reach the socket full control of the Docker daemon, which runs as root.',
    impact:
      'Anyone with access to the socket can start a new privileged container that mounts the ' +
      'host root filesystem, effectively achieving root code execution on the host. This is one ' +
      'of the most common real-world container escape paths, exploited heavily against exposed ' +
      'CI runners and mis-deployed monitoring agents (e.g. cAdvisor, Portainer, Watchtower).',
    detection:
      'docker inspect <container> --format "{{range .Mounts}}{{.Source}} -> {{.Destination}}{{println}}{{end}}" | grep docker.sock\n' +
      'ss -lntp | grep 2375\n' +
      'curl -s http://<host>:2375/version   # unauthenticated daemon check',
    remediation:
      'Never bind-mount docker.sock into containers. If Docker-in-Docker functionality is ' +
      'required, use rootless Docker or a dedicated sandboxed build service (e.g. Kaniko, ' +
      'Buildah) instead. If remote API access is required, enable TLS mutual authentication:\n' +
      'dockerd --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem --tlskey=server-key.pem -H=0.0.0.0:2376',
    cisReference: 'CIS Docker Benchmark 2.1',
  },

  {
    issue: 'Use of the default bridge network',
    risk:
      'The default "bridge" network (docker0) places all containers on it into the same flat ' +
      'L2/L3 broadcast domain with no inter-container network isolation and legacy, insecure ' +
      'inter-container communication (icc=true) enabled by default.',
    impact:
      'A compromised container can perform ARP spoofing, sniff traffic, or directly reach other ' +
      'containers on the same host that were never intended to communicate, enabling lateral ' +
      'movement between otherwise unrelated workloads.',
    detection:
      'docker network inspect bridge --format "{{json .Containers}}"\n' +
      'docker inspect <container> --format "{{.HostConfig.NetworkMode}}"',
    remediation:
      'Create purpose-built user-defined bridge networks per application and disable ' +
      'inter-container communication where not required:\n' +
      'docker network create --opt com.docker.network.bridge.enable_icc=false app-net\n' +
      'docker run --network=app-net myimage',
    cisReference: 'CIS Docker Benchmark 5.29',
  },

  {
    issue: 'No CPU or memory resource limits',
    risk:
      'Containers started without --memory, --memory-swap, --cpus, or --pids-limit can consume ' +
      'unbounded host resources.',
    impact:
      'A single misbehaving or maliciously crafted workload (fork bomb, memory leak, crypto ' +
      'miner) can starve every other container and the host kernel itself of CPU, memory, or ' +
      'process table entries, causing a denial of service across the entire node.',
    detection:
      'docker inspect <container> --format "Memory={{.HostConfig.Memory}} CPUQuota={{.HostConfig.CpuQuota}} PidsLimit={{.HostConfig.PidsLimit}}"\n' +
      'docker stats --no-stream',
    remediation:
      'Always set explicit resource ceilings:\n' +
      'docker run --memory=512m --memory-swap=512m --cpus=1.0 --pids-limit=100 myimage\n' +
      'In Kubernetes, set resources.limits.cpu/memory on every container and enforce a ' +
      'LimitRange and ResourceQuota per namespace.',
    cisReference: 'CIS Docker Benchmark 5.10, 5.11, 5.28',
  },

  {
    issue: 'Running the container process as root (UID 0)',
    risk:
      'The vast majority of official and community images default their ENTRYPOINT/CMD process ' +
      'to run as root inside the container because no USER instruction is set in the Dockerfile.',
    impact:
      'If an attacker achieves code execution inside the container (e.g. via a deserialization ' +
      'or RCE bug in the app), they immediately have root inside the container namespace, which ' +
      'significantly widens the blast radius for any subsequent container-escape or kernel ' +
      'exploit, and makes writable-volume and capability abuse trivial.',
    detection:
      'docker inspect <container> --format "{{.Config.User}}"   # empty means root\n' +
      'docker exec <container> id',
    remediation:
      'Add a dedicated unprivileged user in the Dockerfile and switch to it before the app runs:\n' +
      'RUN addgroup -S app && adduser -S app -G app\n' +
      'USER app\n' +
      'Also enforce at runtime with --user 1000:1000 and set ' +
      'securityContext.runAsNonRoot: true / runAsUser in Kubernetes PodSpecs.',
    cisReference: 'CIS Docker Benchmark 4.1',
  },

  {
    issue: 'Mounting sensitive host paths',
    risk:
      'Bind-mounting sensitive host directories such as /, /etc, /proc, /var/run, /root, or ' +
      'cloud metadata credential directories into a container exposes host configuration and ' +
      'secrets directly to container processes.',
    impact:
      'A compromised container with access to /etc/shadow, SSH keys, cloud IAM credential files, ' +
      'or /proc can read host secrets, modify host configuration, or leverage /proc/sys writes ' +
      'and cgroup release_agent tricks to escape to the host entirely.',
    detection:
      'docker inspect <container> --format "{{range .Mounts}}{{.Source}}:{{.Destination}} ({{.RW}}){{println}}{{end}}"',
    remediation:
      'Mount only the minimum required paths, read-only wherever possible:\n' +
      'docker run -v /app/config:/config:ro myimage\n' +
      'Never mount /, /etc, /proc, /sys, /var/run/docker.sock, or cloud credential directories ' +
      'unless absolutely required and access-controlled.',
    cisReference: 'CIS Docker Benchmark 5.5, 5.31',
  },

  {
    issue: 'Outdated or unpatched base images',
    risk:
      'Building on stale base images (e.g. ubuntu:18.04, node:12, or images pinned to a "latest" ' +
      'tag from months ago) means the image ships with known, patched CVEs in the OS packages ' +
      'and language runtime.',
    impact:
      'Attackers routinely scan public-facing services for known CVEs in outdated packages ' +
      '(OpenSSL, glibc, curl, log4j, etc.) to gain remote code execution or privilege escalation ' +
      'inside the container.',
    detection:
      'trivy image myapp:latest\n' +
      'grype myapp:latest\n' +
      'docker scout cves myapp:latest',
    remediation:
      'Pin base images to minimal, actively maintained variants (distroless, alpine, chainguard) ' +
      'and rebuild on a schedule with automated CVE scanning in CI:\n' +
      'FROM node:20.11-alpine3.19\n' +
      'Add a scheduled pipeline job running "trivy image --exit-code 1 --severity HIGH,CRITICAL" ' +
      'to fail builds on newly disclosed CVEs.',
    cisReference: 'CIS Docker Benchmark 4.7',
  },

  {
    issue: 'Embedded secrets in image layers',
    risk:
      'Hard-coding API keys, database passwords, TLS private keys, or cloud credentials directly ' +
      'in a Dockerfile via ENV, ARG, or COPY, or passing them as build --build-arg values, bakes ' +
      'them permanently into the image layer history even if later deleted in a subsequent layer.',
    impact:
      'Anyone with pull access to the image (registry breach, misconfigured public registry, or ' +
      'a former employee with old credentials) can extract secrets with "docker history" or by ' +
      'unpacking layer tarballs, even if the file was removed in a later RUN step.',
    detection:
      'docker history --no-trunc myimage\n' +
      'trivy image --scanners secret myimage\n' +
      'gitleaks detect --source . --no-git   # for Dockerfile/repo scanning',
    remediation:
      'Never embed secrets in Dockerfiles. Use BuildKit secret mounts, which are never persisted ' +
      'in the final image:\n' +
      '# syntax=docker/dockerfile:1\n' +
      'RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm install\n' +
      'docker build --secret id=npmrc,src=$HOME/.npmrc .\n' +
      'Inject runtime secrets via orchestrator secret managers (Kubernetes Secrets backed by ' +
      'a KMS, HashiCorp Vault, AWS Secrets Manager) instead.',
    cisReference: 'CIS Docker Benchmark 4.10',
  },

  {
    issue: 'No health checks defined',
    risk:
      'Omitting a HEALTHCHECK instruction means the container runtime has no application-level ' +
      'signal of liveness beyond the top-level process staying alive.',
    impact:
      'A container whose main process is running but whose application has hung, deadlocked, or ' +
      'entered a compromised/backdoored state (e.g. a reverse shell replacing the intended ' +
      'service) will continue receiving traffic and passing orchestrator liveness checks, ' +
      'delaying detection and automated remediation.',
    detection:
      'docker inspect <container> --format "{{.State.Health.Status}}"\n' +
      'docker inspect <container> --format "{{json .Config.Healthcheck}}"',
    remediation:
      'Define an explicit, meaningful health check:\n' +
      'HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD curl -f http://localhost:8080/healthz || exit 1\n' +
      'In Kubernetes, pair this with livenessProbe and readinessProbe definitions so the ' +
      'kubelet restarts or removes-from-service unhealthy pods automatically.',
    cisReference: 'CIS Docker Benchmark 4.6',
  },

  {
    issue: 'Writable root filesystem',
    risk:
      'By default a container\'s root filesystem is writable, allowing any process inside the ' +
      'container to modify binaries, drop new executables, or persist a backdoor within the ' +
      'container filesystem.',
    impact:
      'An attacker with code execution can overwrite application binaries or configuration, ' +
      'install persistence (cron jobs, modified entrypoints, LD_PRELOAD hijacks), or tamper with ' +
      'audit trails, all of which survive as long as the container runs.',
    detection:
      'docker inspect <container> --format "{{.HostConfig.ReadonlyRootfs}}"',
    remediation:
      'Run with a read-only root filesystem and mount explicit writable tmpfs volumes only for ' +
      'paths that truly need to be written (logs, cache, tmp):\n' +
      'docker run --read-only --tmpfs /tmp --tmpfs /var/run myimage\n' +
      'In Kubernetes set securityContext.readOnlyRootFilesystem: true.',
    cisReference: 'CIS Docker Benchmark 5.12',
  },

  {
    issue: 'Excessive Linux capabilities',
    risk:
      'Docker grants a default capability set (including CAP_NET_RAW, CAP_SETUID, CAP_SETGID, ' +
      'CAP_SYS_CHROOT, etc.) to every container, most of which the application never needs, and ' +
      'operators frequently add more (--cap-add=ALL, --cap-add=SYS_ADMIN) to work around ' +
      'permission errors instead of diagnosing the real cause.',
    impact:
      'Capabilities such as CAP_SYS_ADMIN, CAP_SYS_MODULE, or CAP_SYS_PTRACE are near-equivalent ' +
      'to full root and are frequently used in published container-escape techniques (mounting ' +
      'cgroups, loading kernel modules, ptracing host processes) to break out of the container ' +
      'namespace.',
    detection:
      'docker inspect <container> --format "{{.HostConfig.CapAdd}} / dropped: {{.HostConfig.CapDrop}}"\n' +
      'getpcaps $(docker inspect -f "{{.State.Pid}}" <container>)',
    remediation:
      'Drop all capabilities and add back only the exact ones required:\n' +
      'docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE myimage\n' +
      'In Kubernetes, set securityContext.capabilities.drop: ["ALL"] and add only what is needed ' +
      'per container.',
    cisReference: 'CIS Docker Benchmark 5.3',
  },

  {
    issue: 'Sharing the host PID or network namespace',
    risk:
      '--pid=host and --network=host remove the process ID and network namespace isolation ' +
      'between the container and the host, letting the container see and interact with every ' +
      'process and network interface on the host.',
    impact:
      'A container with --pid=host can signal, ptrace, or read /proc/<pid>/environ and ' +
      '/proc/<pid>/fd of any host process, potentially harvesting credentials or environment ' +
      'secrets from unrelated workloads. --network=host removes network segmentation and lets ' +
      'the container bind to any host port and sniff host network traffic.',
    detection:
      'docker inspect <container> --format "PidMode={{.HostConfig.PidMode}} NetworkMode={{.HostConfig.NetworkMode}}"',
    remediation:
      'Avoid host namespace sharing entirely unless there is a specific, reviewed operational ' +
      'need (e.g. a host-level monitoring agent). Prefer named, isolated namespaces and explicit ' +
      'published ports:\n' +
      'docker run -p 8080:8080 myimage\n' +
      'In Kubernetes, hostPID and hostNetwork should be disallowed by the PodSecurity ' +
      '"restricted"/"baseline" policy.',
    cisReference: 'CIS Docker Benchmark 5.15, 5.9',
  },

  {
    issue: 'No security profile enforcement (AppArmor / seccomp / SELinux)',
    risk:
      'Running with --security-opt seccomp=unconfined or --security-opt apparmor=unconfined ' +
      'disables the default seccomp syscall filter and AppArmor/SELinux mandatory access control ' +
      'profile that Docker applies by default.',
    impact:
      'Without seccomp filtering, a compromised process can invoke dangerous or rarely used ' +
      'syscalls (e.g. ptrace, mount, kexec_load, perf_event_open) that are commonly leveraged in ' +
      'container escape and kernel-exploitation chains and would otherwise be blocked by the ' +
      'default profile.',
    detection:
      'docker inspect <container> --format "{{.HostConfig.SecurityOpt}}"\n' +
      'docker info --format "{{.SecurityOptions}}"',
    remediation:
      'Never disable the default seccomp/AppArmor profiles. Use a custom, tightened seccomp ' +
      'profile for extra restriction where the default is still too permissive:\n' +
      'docker run --security-opt seccomp=./custom-seccomp.json --security-opt apparmor=docker-default myimage\n' +
      'In Kubernetes, set securityContext.seccompProfile.type: RuntimeDefault (or Localhost with ' +
      'a custom profile).',
    cisReference: 'CIS Docker Benchmark 5.21, 5.1',
  },

  {
    issue: 'Pulling images from insecure or unverified registries',
    risk:
      'Configuring the Docker daemon with insecure-registries (plain HTTP) or pulling images ' +
      'from public registries without digest pinning or signature verification allows images to ' +
      'be tampered with in transit or silently replaced upstream.',
    impact:
      'A man-in-the-middle on an HTTP registry connection, or a compromised/typosquatted public ' +
      'image, can deliver a backdoored image that is pulled and run with full trust, resulting in ' +
      'supply-chain compromise across every host that deploys it.',
    detection:
      'cat /etc/docker/daemon.json | jq ".insecure-registries"\n' +
      'docker inspect --format "{{.RepoDigests}}" myimage   # verify pinned by digest',
    remediation:
      'Only use TLS-secured registries, pin production images by digest, and enable content ' +
      'trust / cosign signature verification:\n' +
      'docker pull myregistry.io/app@sha256:3f8a...\n' +
      'export DOCKER_CONTENT_TRUST=1\n' +
      'cosign verify --key cosign.pub myregistry.io/app:1.4.0',
    cisReference: 'CIS Docker Benchmark 4.5, 2.5',
  },

  {
    issue: 'Overly permissive volume mount options (rw everywhere)',
    risk:
      'Defaulting every bind mount and named volume to read-write, even for configuration, code, ' +
      'or reference data that the container never needs to modify.',
    impact:
      'A compromised application can tamper with configuration files, application code shared ' +
      'with other containers, or reference/static data, enabling persistence or a pivot to other ' +
      'services sharing the same volume.',
    detection:
      'docker inspect <container> --format "{{range .Mounts}}{{.Destination}}:{{.RW}}{{println}}{{end}}"',
    remediation:
      'Mount as read-only by default and only grant write access to the specific paths that need ' +
      'it:\n' +
      'docker run -v appdata:/data:ro -v applogs:/var/log/app:rw myimage',
    cisReference: 'CIS Docker Benchmark 5.31',
  },

  {
    issue: 'Lack of image provenance / unsigned images in production',
    risk:
      'Deploying images without verifying their build provenance (who built it, from what ' +
      'source, with what dependencies) makes it impossible to distinguish a legitimate build ' +
      'from a tampered one.',
    impact:
      'Supply-chain attacks (such as a compromised CI pipeline or a malicious dependency in the ' +
      'build) can inject malware into an image that otherwise appears legitimate and passes ' +
      'through to production undetected.',
    detection:
      'cosign verify-attestation --key cosign.pub myregistry.io/app:1.4.0\n' +
      'docker trust inspect --pretty myimage',
    remediation:
      'Sign images at build time and enforce signature verification at deploy time using ' +
      'cosign/Sigstore and an admission controller such as Kyverno or Connaisseur:\n' +
      'cosign sign --key cosign.key myregistry.io/app:1.4.0\n' +
      'Configure a Kyverno ClusterPolicy with verifyImages to reject unsigned images at ' +
      'admission time.',
    cisReference: 'CIS Docker Benchmark 4.10 (NIST SP 800-190 Sec. 4.3)',
  },

  {
    issue: 'Container logging not centralized or tamper-evident',
    risk:
      'Relying on the default json-file logging driver with unbounded log size and no forwarding ' +
      'to a central, access-controlled log store leaves logs stored only on the ephemeral ' +
      'container/host filesystem.',
    impact:
      'An attacker with container or host access can delete or modify local logs to erase ' +
      'evidence of compromise, and unbounded logs can fill host disk causing a denial of service.',
    detection:
      'docker inspect <container> --format "{{.HostConfig.LogConfig}}"',
    remediation:
      'Configure a bounded, centralized logging driver and forward logs off-host in real time:\n' +
      'docker run --log-driver=json-file --log-opt max-size=10m --log-opt max-file=3 myimage\n' +
      'Or ship to a SIEM using --log-driver=syslog / fluentd / gelf, and in Kubernetes deploy a ' +
      'DaemonSet log forwarder (Fluent Bit) shipping to an immutable, access-controlled backend.',
    cisReference: 'CIS Docker Benchmark 2.12, 2.13',
  },

  {
    issue: 'Docker daemon exposed without TLS client authentication',
    risk:
      'Enabling the Docker remote API (-H tcp://0.0.0.0:2375) without TLS client certificate ' +
      'verification lets any network-reachable client issue arbitrary Docker API calls.',
    impact:
      'Internet-wide scanning campaigns actively hunt for port 2375 exposed to the internet; ' +
      'once found, attackers immediately deploy cryptomining containers or reverse shells with ' +
      'full host-mounting privileged containers, a very common real-world cloud compromise ' +
      'vector.',
    detection:
      'nmap -p 2375,2376 <host>\n' +
      'curl http://<host>:2375/containers/json   # succeeds = unauthenticated access',
    remediation:
      'Disable the unauthenticated TCP socket; if remote API access is required, bind only to ' +
      'localhost or a private network and require mutual TLS:\n' +
      'dockerd --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem --tlskey=server-key.pem -H=127.0.0.1:2376',
    cisReference: 'CIS Docker Benchmark 2.1, 2.6',
  },

  {
    issue: 'Not restricting inter-container communication and default userland proxy risks',
    risk:
      'Leaving icc (inter-container communication) enabled on user-defined networks and running ' +
      'many unrelated services on one shared network means every container can reach every ' +
      'other container by default.',
    impact:
      'A single compromised low-value container (e.g. a marketing microsite) can pivot directly ' +
      'to high-value internal services (databases, internal admin panels) on the same Docker ' +
      'network with no additional network control in the way.',
    detection:
      'docker network inspect <network> --format "{{json .Options}}"',
    remediation:
      'Segment applications into distinct networks by trust boundary and disable icc where cross ' +
      'talk is not required:\n' +
      'docker network create --opt com.docker.network.bridge.enable_icc=false backend-net\n' +
      'Explicitly docker network connect only the services that must communicate.',
    cisReference: 'CIS Docker Benchmark 5.29',
  },

  {
    issue: 'Missing image build-time vulnerability gating in CI/CD',
    risk:
      'CI/CD pipelines that build and push images without a vulnerability scanning gate allow ' +
      'images with known critical CVEs to reach production registries unchecked.',
    impact:
      'Known, easily exploitable vulnerabilities accumulate silently in the fleet, and are only ' +
      'discovered reactively (often by an attacker) rather than being blocked before deployment.',
    detection:
      'Review CI pipeline definitions (.gitlab-ci.yml, Jenkinsfile, GitHub Actions workflow) for ' +
      'absence of a scan-and-fail step after the docker build stage.',
    remediation:
      'Add a mandatory scanning gate that fails the build on HIGH/CRITICAL findings:\n' +
      'trivy image --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed myapp:$CI_COMMIT_SHA\n' +
      'Combine with Grype/Snyk Container as a second opinion and periodically re-scan already ' +
      'deployed images for newly disclosed CVEs.',
    cisReference: 'NIST SP 800-190 Sec. 4.1 (CIS Docker Benchmark 4.7 supporting control)',
  },

  {
    issue: 'Running SSH daemons or unnecessary services inside containers',
    risk:
      'Baking an sshd, cron, or full init system into an application container to allow ' +
      '"logging in" for debugging violates the single-process-per-container model and expands ' +
      'the container attack surface unnecessarily.',
    impact:
      'Extra long-running daemons introduce additional listening ports, additional patchable ' +
      'surface, and additional credentials (SSH keys/passwords) that must be managed and can be ' +
      'brute-forced or leaked, none of which is needed for the application to function.',
    detection:
      'docker exec <container> ps aux\n' +
      'docker exec <container> ss -lntp',
    remediation:
      'Keep containers single-purpose; use "docker exec" for debugging access instead of sshd, ' +
      'and use a minimal init (tini, dumb-init, or --init) only for signal/zombie-reaping, not a ' +
      'full service manager:\n' +
      'docker run --init myimage',
    cisReference: 'CIS Docker Benchmark 4.9',
  },

  {
    issue: 'No image tag immutability (mutable "latest" tag in production)',
    risk:
      'Deploying with a floating tag such as "latest" or "stable" means the exact image content ' +
      'running in production can change silently whenever the tag is re-pushed, and rollbacks ' +
      'become unreliable.',
    impact:
      'A malicious or accidental push to the "latest" tag (e.g. via a compromised CI credential) ' +
      'is automatically pulled by auto-updating deployments, and there is no reliable audit trail ' +
      'of exactly what code was running at a given time during an incident investigation.',
    detection:
      'docker inspect --format "{{.RepoDigests}}" myimage\n' +
      'kubectl get deploy -o jsonpath="{.items[*].spec.template.spec.containers[*].image}" | tr -s "[[:space:]]" "\\n" | grep -E ":latest$"',
    remediation:
      'Use immutable, content-addressable digests or strict semver tags in deployment manifests, ' +
      'and enable registry tag immutability where supported:\n' +
      'image: myregistry.io/app@sha256:3f8a1c9e...\n' +
      'Enforce with an admission policy (Kyverno/OPA Gatekeeper) that rejects ":latest" or ' +
      'untagged images.',
    cisReference: 'CIS Kubernetes Benchmark 5.7.4 (image provenance) / NIST SP 800-190 Sec. 4.1',
  },
];

// =============================================================================
// 2. K8S_ATTACK_TECHNIQUES
// =============================================================================

const K8S_ATTACK_TECHNIQUES = [

  {
    name: 'Exposed Kubernetes Dashboard',
    description:
      'The Kubernetes Dashboard is a web UI for cluster management. When deployed with an overly ' +
      'permissive service account, exposed via a public LoadBalancer/NodePort, or accessible ' +
      'without authentication (a legacy default in dashboard versions prior to 2.0 that granted ' +
      'the "cluster-admin skip login" option), it becomes a direct point-and-click path to full ' +
      'cluster compromise. This was exploited at scale by cryptomining campaigns (e.g. against ' +
      'Tesla\'s exposed dashboard in 2018) that discovered internet-facing dashboards via mass ' +
      'scanning.',
    prerequisites: [
      'Dashboard service exposed externally (NodePort, LoadBalancer, or Ingress without auth)',
      'Dashboard bound to a service account with broad RBAC permissions',
      'No network policy restricting access to the dashboard pod',
    ],
    exploitationSteps: [
      '1. Scan for exposed dashboards: shodan search "port:30000 kubernetes-dashboard" or masscan on common NodePort ranges (30000-32767).',
      '2. Confirm accessibility: curl -k https://<target>:<port>/api/v1/namespace',
      '3. If "skip login" / no auth is enabled, browse to the dashboard UI directly.',
      '4. From the UI, navigate to Workloads and create a new Deployment/Pod using the dashboard\'s "Create from form" or YAML editor.',
      '5. Define a pod spec that mounts the host filesystem and runs privileged: true to escape to the node:\n   spec: containers: [{image: alpine, command: ["chroot","/host","/bin/sh"], securityContext: {privileged: true}, volumeMounts: [{name: host, mountPath: /host}]}], volumes: [{name: host, hostPath: {path: "/"}}]',
      '6. Use the dashboard\'s "Exec" terminal feature on the created pod to obtain a shell with host root access.',
    ],
    detection:
      'Alert on dashboard service exposure via cloud security posture checks; audit-log entries ' +
      'showing dashboard-related service account creating pods with hostPath/privileged; ' +
      'kubectl get svc -A -o wide | grep dashboard to confirm ClusterIP-only exposure.',
    mitigation:
      'Never expose the dashboard externally; access it only via "kubectl proxy" or an ' +
      'authenticated, network-restricted Ingress with OIDC. Bind the dashboard service account ' +
      'to a minimal RBAC Role, and upgrade to Dashboard v2+ which requires a bearer token by ' +
      'default.',
    severity: 'Critical',
  },

  {
    name: 'Anonymous authentication to the Kubernetes API server',
    description:
      'Kubernetes API servers historically defaulted --anonymous-auth=true. Combined with an ' +
      'overly permissive ClusterRoleBinding for the system:anonymous user or system:unauthenticated ' +
      'group (a well-documented misconfiguration seen in several cloud provider managed clusters ' +
      'and self-managed installs), this allows unauthenticated requests to be treated as a real ' +
      'identity with real permissions.',
    prerequisites: [
      'API server reachable from the attacker\'s network position',
      '--anonymous-auth=true (default in many distributions)',
      'A ClusterRoleBinding granting the system:unauthenticated group meaningful permissions',
    ],
    exploitationSteps: [
      '1. Discover the API server endpoint (cloud metadata, DNS, or port scan on 6443/8080).',
      '2. Test anonymous access: curl -k https://<api-server>:6443/api/v1/namespaces --header "Authorization:"',
      '3. Enumerate what the anonymous user can do: kubectl auth can-i --list --token="" --server=https://<api-server>:6443',
      '4. If pod creation is allowed, deploy a malicious pod: kubectl --token="" create -f malicious-pod.yaml',
      '5. If only read access is granted, harvest Secrets/ConfigMaps for credentials: kubectl --token="" get secrets -A -o json',
    ],
    detection:
      'Audit logs showing requests from user "system:anonymous"; kube-bench check 1.2.1 flagging ' +
      'anonymous-auth enabled; regularly run kubectl auth can-i --list --as=system:anonymous.',
    mitigation:
      'Set --anonymous-auth=false on the API server where feasible, and audit/remove any ' +
      'RoleBinding or ClusterRoleBinding referencing system:anonymous or system:unauthenticated. ' +
      'Managed clusters (EKS/GKE/AKS) should restrict API server endpoint access to private ' +
      'networks or authorized IP ranges.',
    severity: 'Critical',
  },

  {
    name: 'RBAC misconfiguration — overly permissive Roles/ClusterRoles',
    description:
      'Granting wildcard verbs/resources (verbs: ["*"], resources: ["*"]) or dangerous verb ' +
      'combinations such as "create pods", "create pods/exec", "bind", "escalate", or "impersonate" ' +
      'to service accounts, especially the default service account of a namespace, effectively ' +
      'grants privilege escalation paths to any workload using that identity.',
    prerequisites: [
      'A pod or CI job running with a service account token that has excess RBAC permissions',
      'Ability to make API calls with that token (in-cluster or exfiltrated)',
    ],
    exploitationSteps: [
      '1. From inside a compromised pod, read the mounted service account token:\n   TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)',
      '2. Enumerate effective permissions: kubectl --token=$TOKEN auth can-i --list',
      '3. If "create" on pods is allowed cluster-wide, deploy a pod using a more privileged service account (e.g. one bound to cluster-admin) to escalate:\n   kubectl --token=$TOKEN run pwn --image=alpine --overrides=\'{"spec":{"serviceAccountName":"cluster-admin-sa"}}\' -- sleep 3600',
      '4. If "bind" or "escalate" verbs are allowed on roles/clusterroles, create a new ClusterRoleBinding granting the current service account cluster-admin directly.',
      '5. If "impersonate" is allowed, add an Impersonate-User header to act as a higher-privileged user: kubectl --token=$TOKEN --as=system:admin get secrets -A',
    ],
    detection:
      'kube-bench and kubeaudit RBAC checks; periodically run "kubectl-who-can" or rbac-lookup ' +
      'against the cluster; audit for ClusterRoleBindings referencing "default" service accounts.',
    mitigation:
      'Apply least-privilege RBAC: never bind cluster-admin to workload service accounts, disable ' +
      'automountServiceAccountToken where the API is not needed, and use tools like ' +
      'rbac-police/audit2rbac to derive minimal roles from actual usage.',
    severity: 'High',
  },

  {
    name: 'Container/pod escape via privileged containers or dangerous mounts',
    description:
      'Pods scheduled with securityContext.privileged: true, or with a hostPath mount of ' +
      'sensitive host paths (/, /var/run/docker.sock, /proc, cgroup filesystems), give the ' +
      'container process a direct path to escape the container namespace and execute code as ' +
      'root on the underlying node.',
    prerequisites: [
      'Ability to create or modify a PodSpec (via RBAC, CI/CD pipeline compromise, or a ' +
        'vulnerable admission-controller-free cluster)',
      'No PodSecurity Standard ("restricted"/"baseline") or OPA/Kyverno policy blocking ' +
        'privileged pods or hostPath mounts',
    ],
    exploitationSteps: [
      '1. Deploy a pod requesting privileged mode and a hostPath root mount:\n   securityContext: {privileged: true}\n   volumeMounts: [{name: host, mountPath: /host}]\n   volumes: [{name: host, hostPath: {path: "/"}}]',
      '2. Exec into the pod and chroot into the mounted host filesystem: kubectl exec -it pwn -- chroot /host /bin/bash',
      '3. From the chroot, read node-level secrets (kubelet client certs at /etc/kubernetes/pki, cloud-init credentials) or add an SSH key to gain persistent node access.',
      '4. Alternatively, exploit the well-known cgroup release_agent technique from a privileged container without a hostPath mount to trigger arbitrary command execution on the host.',
    ],
    detection:
      'Falco default rules "Launch Privileged Container" and "Terminal shell in container"; ' +
      'kube-bench 5.2.x checks against Pod Security admission; audit logs for pod creation ' +
      'requests with privileged:true or hostPath volumes.',
    mitigation:
      'Enforce the Pod Security Standards "restricted" profile at the namespace level (or ' +
      'OPA Gatekeeper / Kyverno policies) to reject privileged pods, hostPath volumes, and ' +
      'dangerous capabilities cluster-wide.',
    severity: 'Critical',
  },

  {
    name: 'Service account token theft and abuse',
    description:
      'Every pod, by default, has its namespace service account token automounted at ' +
      '/var/run/secrets/kubernetes.io/serviceaccount/token. If an attacker achieves arbitrary ' +
      'file read or code execution in any pod (e.g. via an SSRF, LFI, or RCE vulnerability in ' +
      'the application), they can read this token and use it to authenticate to the API server ' +
      'as that pod\'s identity, inheriting whatever RBAC permissions it holds.',
    prerequisites: [
      'A file-read or RCE primitive in an application running inside a pod',
      'automountServiceAccountToken not disabled for that pod/service account',
    ],
    exploitationSteps: [
      '1. Via the application vulnerability, read the token file: cat /var/run/secrets/kubernetes.io/serviceaccount/token',
      '2. Also grab the CA cert and namespace: cat .../ca.crt and cat .../namespace',
      '3. Use the token to talk to the API server directly:\n   curl -s --cacert ca.crt -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/<ns>/secrets',
      '4. Enumerate and exfiltrate any Secrets, ConfigMaps, or resources the token\'s RBAC role permits.',
      '5. If the token has broader permissions (misconfigured RBAC), pivot to full-cluster compromise as in the RBAC misconfiguration technique above.',
    ],
    detection:
      'Audit log entries showing API calls from a service account originating outside expected ' +
      'source pods/IPs; Falco rule "Contact K8S API Server From Container"; anomaly detection on ' +
      'service account usage patterns.',
    mitigation:
      'Set automountServiceAccountToken: false on service accounts/pods that do not need API ' +
      'access; use time-bound projected service account tokens (TokenRequest API, the default ' +
      'since Kubernetes 1.22 "BoundServiceAccountTokenVolume") instead of long-lived static ' +
      'tokens; apply least-privilege RBAC per workload.',
    severity: 'High',
  },

  {
    name: 'Direct etcd access',
    description:
      'etcd stores all Kubernetes cluster state, including Secrets, in a key-value store. By ' +
      'default Secrets are only base64-encoded (not encrypted) in etcd unless encryption-at-rest ' +
      'is explicitly configured. If etcd is reachable over the network without mutual TLS, or if ' +
      'an attacker gains node access to an etcd member, all cluster secrets can be extracted ' +
      'directly, bypassing RBAC entirely.',
    prerequisites: [
      'Network access to the etcd client port (2379) or peer port (2380)',
      'Missing or misconfigured client certificate authentication on etcd',
      'No encryption-at-rest (EncryptionConfiguration) applied to Secrets',
    ],
    exploitationSteps: [
      '1. Discover etcd endpoints (control-plane node IPs on port 2379).',
      '2. Test unauthenticated access: etcdctl --endpoints=https://<etcd-ip>:2379 get / --prefix --keys-only',
      '3. If client certs are required but were exfiltrated from a compromised control-plane node (/etc/kubernetes/pki/etcd/), use them: etcdctl --cacert=ca.crt --cert=client.crt --key=client.key --endpoints=https://<etcd-ip>:2379 get /registry/secrets --prefix',
      '4. Base64-decode extracted secret values to recover credentials, TLS keys, and tokens for every namespace in the cluster.',
    ],
    detection:
      'Network monitoring for unexpected connections to port 2379/2380 from outside the ' +
      'control-plane; etcd audit/access logs; kube-bench control-plane checks 2.x (etcd TLS ' +
      'configuration).',
    mitigation:
      'Restrict etcd network access to control-plane nodes only (firewall/security group), ' +
      'require and rotate client certificates (--client-cert-auth=true), and enable Secrets ' +
      'encryption at rest via an EncryptionConfiguration using a KMS provider.',
    severity: 'Critical',
  },

  {
    name: 'Kubelet API abuse (unauthenticated / anonymous kubelet)',
    description:
      'The kubelet exposes an HTTPS API on port 10250 (and historically a read-only HTTP API on ' +
      '10255) that allows listing and executing commands in pods on that node. Kubelets ' +
      'configured with --anonymous-auth=true or a permissive --authorization-mode=AlwaysAllow ' +
      'allow unauthenticated remote command execution in any pod scheduled on that node.',
    prerequisites: [
      'Network access to the kubelet port (10250/10255) on a worker node',
      'Kubelet anonymous auth enabled or AlwaysAllow authorization mode',
    ],
    exploitationSteps: [
      '1. Scan for exposed kubelet ports: nmap -p 10250,10255 <node-ip-range> (this is exactly what the kube-hunter tool automates).',
      '2. List running pods on the node: curl -k https://<node>:10250/pods',
      '3. Execute a command inside a chosen pod/container via the kubelet exec API: curl -k -X POST "https://<node>:10250/exec/<namespace>/<pod>/<container>?command=id&input=1&output=1&tty=1"',
      '4. Use the obtained shell to read that pod\'s mounted service account token and pivot further into the cluster as described in the token-abuse technique.',
    ],
    detection:
      'kube-hunter and kube-bench flag anonymous kubelet access; audit logs on the kubelet; ' +
      'network policies/firewalls should log denied connections to 10250 from non-control-plane sources.',
    mitigation:
      'Set --anonymous-auth=false and --authorization-mode=Webhook on every kubelet, disable the ' +
      'deprecated read-only port entirely (--read-only-port=0), and restrict network access to ' +
      'the kubelet API to the API server only.',
    severity: 'Critical',
  },

  {
    name: 'Privileged pods used as a pivot from namespace to cluster/node compromise',
    description:
      'Even in clusters with reasonable namespace-level RBAC isolation, a single namespace that ' +
      'permits privileged pods (no Pod Security admission enforced) becomes the weakest link: ' +
      'compromising any application in that namespace lets an attacker deploy a privileged pod, ' +
      'escape to the node, and from the node reach every other namespace\'s workloads and secrets ' +
      'via the local kubelet credentials and network access.',
    prerequisites: [
      'RBAC permission to create pods in at least one namespace',
      'That namespace lacking a "restricted" Pod Security Standard label or equivalent policy',
    ],
    exploitationSteps: [
      '1. Confirm pod creation rights: kubectl auth can-i create pods -n target-namespace',
      '2. Deploy a privileged pod with a hostPath mount as shown in the escape technique above.',
      '3. From the compromised node, read the kubelet\'s client certificate at /var/lib/kubelet/pki/ to impersonate the node identity to the API server.',
      '4. Use the node\'s credentials (system:node:<name>) to read Secrets and ConfigMaps mounted to pods scheduled on that same node across other namespaces (Node authorizer normally limits this, but misconfigurations can widen it).',
    ],
    detection:
      'Falco privileged container rules; kube-bench 5.2 series (Pod Security Policy / Pod ' +
      'Security admission checks); regular audits of namespace labels for ' +
      'pod-security.kubernetes.io/enforce=restricted.',
    mitigation:
      'Enforce Pod Security Standards at "restricted" for all application namespaces by default, ' +
      'reserving "privileged" only for a small, tightly controlled set of system namespaces.',
    severity: 'High',
  },

  {
    name: 'Malicious or compromised container images (supply-chain attack)',
    description:
      'Kubernetes will happily pull and run any image referenced in a PodSpec. Attackers publish ' +
      'typosquatted images to public registries (e.g. "kube-system/nginx" lookalikes), compromise ' +
      'legitimate base images upstream, or inject malicious code into CI/CD build pipelines that ' +
      'produce the organization\'s own images, resulting in cluster-wide compromise the moment the ' +
      'poisoned image is deployed.',
    prerequisites: [
      'No image signature verification or registry allowlisting enforced by an admission controller',
      'Developers/CI pulling images from public registries without pinning by digest',
    ],
    exploitationSteps: [
      '1. Attacker publishes a malicious image to a public registry with a name resembling a popular package, or compromises a legitimate upstream base image / dependency.',
      '2. A developer or automated pipeline references the image by mutable tag (e.g. FROM popular-base:latest) and it gets pulled into the build or deployed directly.',
      '3. On first run, the malicious image executes an embedded payload (reverse shell, crypto miner, or credential harvester) using whatever service account and network access the deploying pod has.',
      '4. The attacker uses that initial foothold to enumerate the cluster and escalate via any of the other techniques listed here (RBAC abuse, token theft, privileged escape).',
    ],
    detection:
      'Image scanning in CI (Trivy/Grype/Snyk) catching known-malicious or vulnerable packages; ' +
      'runtime detection via Falco for unexpected outbound connections or process execution not ' +
      'matching the image\'s expected behavior; SBOM diffing between builds.',
    mitigation:
      'Enforce an admission policy (Kyverno/OPA Gatekeeper) restricting image pulls to an ' +
      'allowlisted set of internal registries, require cosign signature verification, pin images ' +
      'by digest, and generate/verify SBOMs (Syft) for every build.',
    severity: 'High',
  },

  {
    name: 'Secrets stored in plaintext environment variables',
    description:
      'Injecting sensitive values (database passwords, API keys, TLS private keys) directly as ' +
      'plaintext env vars in a PodSpec, or referencing a Secret via envFrom without further ' +
      'protection, exposes those values to anything that can read the PodSpec (kubectl describe, ' +
      'the Kubernetes API, or any process able to read /proc/1/environ inside the container) and ' +
      'to any logging or crash-dump system that captures process environments.',
    prerequisites: [
      'RBAC read access to pods/deployments (kubectl get pod -o yaml) or code execution inside ' +
        'the pod',
    ],
    exploitationSteps: [
      '1. With read access to pod specs: kubectl get pod <pod> -o jsonpath="{.spec.containers[*].env}"',
      '2. From inside a compromised container in the same pod (multi-container pods share process visibility with shareProcessNamespace, or via /proc if PID namespace is shared): cat /proc/1/environ',
      '3. Check crash dump / APM / logging systems that may have inadvertently captured process environment variables during an exception.',
      '4. Use recovered credentials (DB passwords, cloud keys) to move laterally to the systems those credentials protect.',
    ],
    detection:
      'Static analysis in CI flagging hardcoded values in manifests; regularly grep deployed ' +
      'manifests for env vars matching secret-like patterns; centralized secret-scanning tools ' +
      '(gitleaks, trufflehog) run against the GitOps repository.',
    mitigation:
      'Mount Secrets as files via volumeMounts rather than environment variables where possible, ' +
      'integrate an external secret manager (Vault, AWS/GCP/Azure secret managers via the ' +
      'External Secrets Operator), and enable encryption at rest for the Secrets resource in etcd.',
    severity: 'Medium',
  },

  {
    name: 'Absence of NetworkPolicy (flat pod network)',
    description:
      'By default, Kubernetes allows all pod-to-pod traffic within a cluster unless a CNI plugin ' +
      'that enforces NetworkPolicy is installed and policies are actually defined. Most clusters ' +
      'run with no NetworkPolicies at all, meaning any compromised pod can reach any other pod or ' +
      'service in any namespace, including internal admin panels, databases, and the metadata API.',
    prerequisites: [
      'A CNI that supports NetworkPolicy is either not installed or no policies are defined',
      'Initial foothold in any single pod in the cluster',
    ],
    exploitationSteps: [
      '1. From a compromised pod, scan the pod CIDR range for other services: nmap -sT -p 80,443,3306,5432,6379,9200 10.244.0.0/16',
      '2. Use Kubernetes DNS service discovery to enumerate services across namespaces: nslookup <svc>.<namespace>.svc.cluster.local, or dump the CoreDNS zone if accessible.',
      '3. Connect directly to discovered internal services (databases, message queues, internal APIs) that were never intended to be reachable from a low-trust application namespace.',
      '4. Exfiltrate data or pivot further using any weak/default credentials found on the internal services.',
    ],
    detection:
      'Network flow logging (Cilium Hubble, Calico flow logs) showing unexpected cross-namespace ' +
      'traffic; periodic audits confirming NetworkPolicy objects exist and cover every namespace.',
    mitigation:
      'Deploy a NetworkPolicy-capable CNI (Calico, Cilium, Weave) and apply a default-deny ' +
      'ingress/egress policy per namespace, then explicitly allow only required traffic paths ' +
      '(see K8S_NETWORK_POLICIES below for example manifests).',
    severity: 'High',
  },

  {
    name: 'SSRF to cloud metadata API from a pod',
    description:
      'Applications with a server-side request forgery (SSRF) vulnerability running on cloud ' +
      'Kubernetes (EKS, GKE, AKS) can be tricked into making requests to the instance metadata ' +
      'service (169.254.169.254), which — unless IMDSv2/workload-identity restrictions are ' +
      'enforced — returns the node\'s IAM/service credentials, from which cluster or cloud-account ' +
      'takeover often follows. This is functionally the container/Kubernetes analogue of the ' +
      'classic Capital One SSRF breach.',
    prerequisites: [
      'An SSRF-vulnerable application endpoint running in a pod',
      'Metadata service reachable from the pod network without hop-limit or IMDSv2 protections',
      'Node IAM role/service account with meaningful cloud permissions attached',
    ],
    exploitationSteps: [
      '1. Identify an SSRF vector (e.g. a URL-fetching feature, webhook, or PDF/image renderer).',
      '2. Craft a request causing the server to fetch the metadata endpoint: GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      '3. Retrieve the node instance role name, then fetch temporary AWS credentials: http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>',
      '4. Use the stolen temporary AWS/GCP/Azure credentials via the cloud CLI/SDK to enumerate and access cloud resources (S3 buckets, other EC2 instances, IAM) beyond the Kubernetes cluster itself.',
    ],
    detection:
      'VPC flow logs / cloud provider metadata access logs showing pod-originated calls to ' +
      '169.254.169.254; Falco custom rule alerting on outbound connections to the metadata IP ' +
      'from application containers; enforce IMDSv2 and monitor for IMDSv1 fallback attempts.',
    mitigation:
      'Enforce IMDSv2 (token-required) on cloud instances, set metadata hop-limit to 1 so it is ' +
      'unreachable from pod network namespaces, use workload identity federation (IRSA on EKS, ' +
      'Workload Identity on GKE) instead of broad node instance roles, and block 169.254.169.254 ' +
      'via NetworkPolicy for pods that do not need it.',
    severity: 'Critical',
  },

  {
    name: 'Admission controller / webhook bypass',
    description:
      'Clusters relying on validating/mutating admission webhooks (OPA Gatekeeper, Kyverno) for ' +
      'security enforcement can be bypassed if the webhook is configured with failurePolicy: ' +
      'Ignore, a narrow namespaceSelector that excludes certain namespaces, or if the webhook ' +
      'service itself becomes unavailable, silently allowing non-compliant (e.g. privileged) ' +
      'workloads through.',
    prerequisites: [
      'RBAC permission to create pods/deployments',
      'A misconfigured ValidatingWebhookConfiguration/MutatingWebhookConfiguration (failurePolicy: Ignore, excluded namespaces, or objectSelector gaps)',
    ],
    exploitationSteps: [
      '1. Enumerate webhook configurations: kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations -o yaml',
      '2. Identify failurePolicy and namespaceSelector/objectSelector exclusions, or a system namespace exempted from policy enforcement.',
      '3. Deploy the intended-to-be-blocked workload (e.g. a privileged pod) into an excluded namespace, or during a window where the webhook service is degraded/unreachable so failurePolicy: Ignore lets the request through.',
      '4. Alternatively, if the attacker can cause the webhook pod itself to crash or be resource-starved (denial of service), Ignore-mode webhooks fail open, admitting any subsequent request.',
    ],
    detection:
      'Regularly audit webhook configurations for failurePolicy: Ignore and any namespace ' +
      'exclusions; monitor webhook pod health/availability; alert on admission requests during ' +
      'webhook downtime windows.',
    mitigation:
      'Set failurePolicy: Fail for all security-relevant admission webhooks, keep the webhook ' +
      'exclusion list minimal and reviewed, and run the webhook service highly available across ' +
      'multiple replicas/nodes.',
    severity: 'Medium',
  },

  {
    name: 'Container breakout via kernel vulnerability exploitation',
    description:
      'Because containers on a node share the host kernel, a local privilege escalation or ' +
      'sandbox-escape vulnerability in the kernel (e.g. Dirty Pipe CVE-2022-0847, ' +
      'runc CVE-2019-5736) can be triggered from inside any container to gain code execution on ' +
      'the host, independent of any Kubernetes-level misconfiguration.',
    prerequisites: [
      'Code execution inside any container on the node',
      'An unpatched kernel or container runtime (runc/containerd) vulnerable to a known escape CVE',
    ],
    exploitationSteps: [
      '1. Fingerprint the kernel and runtime versions from inside the container: uname -a; cat /proc/version; check the runtime via /proc/1/root artifacts or exposed version endpoints.',
      '2. Select a matching public exploit (e.g. the Dirty Pipe PoC for CVE-2022-0847, or the runc /proc/self/exe overwrite technique for CVE-2019-5736).',
      '3. Compile/run the exploit inside the container to overwrite a host binary (e.g. runc itself, or a setuid binary) or otherwise achieve host-level code execution.',
      '4. Confirm host access, e.g. by writing a file outside the container mount namespace or reading host-only files.',
    ],
    detection:
      'Falco rules for anomalous syscalls associated with known exploits; vulnerability scanning ' +
      'of host kernel and container runtime versions; kube-bench worker-node checks for runtime ' +
      'patch levels.',
    mitigation:
      'Keep host kernels and container runtimes patched on an aggressive schedule, run gVisor or ' +
      'Kata Containers for stronger workload isolation on multi-tenant or untrusted-workload ' +
      'nodes, and apply seccomp/AppArmor profiles that block the specific syscalls used by known ' +
      'exploit chains.',
    severity: 'Critical',
  },

  {
    name: 'CoreDNS / cluster DNS poisoning and enumeration',
    description:
      'CoreDNS resolves internal service names cluster-wide. If a pod has write access to the ' +
      'CoreDNS ConfigMap (via excess RBAC) or CoreDNS itself is misconfigured with the "log" and ' +
      '"forward" plugins pointing to an attacker-influenced resolver, an attacker can poison DNS ' +
      'responses cluster-wide, redirecting traffic intended for legitimate services (e.g. an ' +
      'internal payment API) to an attacker-controlled pod.',
    prerequisites: [
      'RBAC write access to the kube-system namespace ConfigMap "coredns", or the ability to ' +
        'deploy a rogue DNS server reachable before the legitimate one',
    ],
    exploitationSteps: [
      '1. Check for write access: kubectl auth can-i update configmap/coredns -n kube-system',
      '2. If permitted, edit the Corefile to add a rewrite rule redirecting a target internal service name to an attacker-controlled ClusterIP: kubectl edit configmap coredns -n kube-system',
      '3. Force CoreDNS pods to reload the new config (they auto-reload on ConfigMap change with the reload plugin, or restart the deployment): kubectl rollout restart deployment coredns -n kube-system',
      '4. Wait for application pods to resolve the poisoned name and connect to the attacker-controlled service, capturing credentials/traffic (man-in-the-middle).',
    ],
    detection:
      'Audit log entries for configmap updates in kube-system; monitor CoreDNS Corefile diffs via ' +
      'GitOps drift detection; DNS response anomaly monitoring.',
    mitigation:
      'Restrict RBAC write access to kube-system ConfigMaps to cluster administrators only, ' +
      'enable audit logging with alerting on kube-system mutations, and use GitOps with signed, ' +
      'reviewed commits as the sole path to modify core cluster configuration.',
    severity: 'High',
  },

  {
    name: 'Node compromise via cloud provider IAM privilege escalation (IRSA/Workload Identity abuse)',
    description:
      'When workload identity federation (AWS IRSA, GCP Workload Identity) is misconfigured — for ' +
      'example, a namespace-wide trust policy instead of a per-service-account binding, or a ' +
      'service account annotation that any user in the namespace can attach to their own pod — a ' +
      'workload can assume a cloud IAM role/identity far more privileged than it should have, ' +
      'turning a Kubernetes-level foothold into full cloud account compromise.',
    prerequisites: [
      'IRSA/Workload Identity configured with an overly broad trust relationship',
      'RBAC or namespace access allowing the attacker to create a pod with the privileged service account annotation',
    ],
    exploitationSteps: [
      '1. Enumerate service accounts and their IAM role annotations: kubectl get sa -A -o jsonpath="{range .items[*]}{.metadata.namespace}{\"/\"}{.metadata.name}{\": \"}{.metadata.annotations.eks\\.amazonaws\\.com/role-arn}{\"\\n\"}{end}"',
      '2. Identify a service account bound to a highly privileged IAM role that the attacker\'s current RBAC permissions allow them to reference in a new pod within the same namespace.',
      '3. Deploy a pod using that service account: kubectl run pwn --image=amazon/aws-cli --overrides=\'{"spec":{"serviceAccountName":"privileged-sa"}}\' -- sleep 3600',
      '4. From inside the pod, call the cloud SDK/CLI, which automatically picks up the federated credentials: aws sts get-caller-identity, then enumerate/exfiltrate cloud resources according to that role\'s permissions.',
    ],
    detection:
      'CloudTrail/Cloud Audit Logs showing STS AssumeRoleWithWebIdentity calls from unexpected ' +
      'pods/namespaces; periodic review of IAM trust policies for overly broad service account ' +
      'subject conditions (e.g. missing exact namespace:serviceaccount match).',
    mitigation:
      'Scope IRSA/Workload Identity trust policies to an exact namespace and service account name ' +
      '(not wildcards), apply least-privilege IAM policies per role, and restrict RBAC so only ' +
      'authorized owners of a workload can reference its associated service account.',
    severity: 'High',
  },
];

// =============================================================================
// 3. K8S_HARDENING (CIS Kubernetes Benchmark aligned)
// =============================================================================

const K8S_HARDENING = [

  // --- Control Plane -----------------------------------------------------
  {
    id: '1.1.1',
    category: 'Control Plane',
    title: 'Ensure the API server pod specification file permissions are set to 600 or more restrictive',
    description:
      'The kube-apiserver.yaml static pod manifest should not be readable or writable by ' +
      'unauthorized users, since it can reveal control-plane configuration and, if writable, ' +
      'allows arbitrary modification of API server flags.',
    auditCommand: 'stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml',
    remediationCommand: 'chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml',
    impact: 'None; this only restricts local filesystem permissions.',
    scored: true,
  },
  {
    id: '1.2.1',
    category: 'Control Plane',
    title: 'Ensure --anonymous-auth is set to false on the API server',
    description:
      'Disabling anonymous authentication prevents unauthenticated requests from being processed ' +
      'as the system:anonymous user, closing off a common path to unauthorized cluster access.',
    auditCommand: 'ps -ef | grep kube-apiserver | grep -- "--anonymous-auth"',
    remediationCommand: 'Edit /etc/kubernetes/manifests/kube-apiserver.yaml and set --anonymous-auth=false, then let the kubelet restart the static pod.',
    impact: 'Health checks and other endpoints that relied on anonymous access must be reconfigured to authenticate.',
    scored: true,
  },
  {
    id: '1.2.2',
    category: 'Control Plane',
    title: 'Ensure --token-auth-file is not set on the API server',
    description:
      'Static token files are long-lived, cannot be revoked without an API server restart, and ' +
      'are stored in plaintext, making them a weak authentication mechanism compared to ' +
      'certificates or OIDC.',
    auditCommand: 'ps -ef | grep kube-apiserver | grep -- "--token-auth-file"',
    remediationCommand: 'Remove the --token-auth-file flag from the API server manifest and migrate to certificate-based or OIDC authentication.',
    impact: 'Any automation relying on static bearer tokens must migrate to a supported authentication method.',
    scored: true,
  },
  {
    id: '1.2.6',
    category: 'Control Plane',
    title: 'Ensure --kubelet-certificate-authority is set appropriately on the API server',
    description:
      'Configuring the API server to verify the kubelet\'s TLS certificate against a trusted CA ' +
      'prevents man-in-the-middle attacks when the API server communicates with kubelets.',
    auditCommand: 'ps -ef | grep kube-apiserver | grep -- "--kubelet-certificate-authority"',
    remediationCommand: '--kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt',
    impact: 'Kubelets must present certificates signed by the configured CA, requiring proper certificate provisioning.',
    scored: true,
  },
  {
    id: '1.2.16',
    category: 'Control Plane',
    title: 'Ensure --service-account-lookup is set to true on the API server',
    description:
      'When enabled, the API server validates that a presented service account token still ' +
      'corresponds to an existing ServiceAccount object, so tokens for deleted service accounts ' +
      'are immediately invalidated.',
    auditCommand: 'ps -ef | grep kube-apiserver | grep -- "--service-account-lookup"',
    remediationCommand: '--service-account-lookup=true (this is the default in current Kubernetes versions; verify it has not been overridden).',
    impact: 'Negligible performance overhead from the additional lookup.',
    scored: true,
  },
  {
    id: '1.2.20',
    category: 'Control Plane',
    title: 'Ensure --profiling is set to false on the API server',
    description:
      'The pprof profiling endpoint exposes internal runtime data that can aid an attacker in ' +
      'fingerprinting and exploiting the API server and should be disabled in production.',
    auditCommand: 'ps -ef | grep kube-apiserver | grep -- "--profiling"',
    remediationCommand: '--profiling=false',
    impact: 'Reduces available debugging data for performance troubleshooting; use out-of-band profiling in a controlled environment instead.',
    scored: true,
  },
  {
    id: '1.2.22',
    category: 'Control Plane',
    title: 'Ensure --audit-log-path is set on the API server',
    description:
      'Configuring an audit log path ensures every request to the API server is recorded, ' +
      'forming the foundation for detection and forensic investigation of cluster compromise.',
    auditCommand: 'ps -ef | grep kube-apiserver | grep -- "--audit-log-path"',
    remediationCommand: '--audit-log-path=/var/log/kubernetes/audit/audit.log --audit-policy-file=/etc/kubernetes/audit-policy.yaml',
    impact: 'Increases disk I/O and requires log rotation/retention management.',
    scored: true,
  },
  {
    id: '1.2.34',
    category: 'Control Plane',
    title: 'Ensure encryption providers are appropriately configured for Secrets at rest',
    description:
      'Without an EncryptionConfiguration, Secret objects are stored in etcd only base64-encoded, ' +
      'which is trivially reversible; a compromise of etcd or its backups otherwise directly ' +
      'exposes all cluster secrets in cleartext.',
    auditCommand: 'ps -ef | grep kube-apiserver | grep -- "--encryption-provider-config"',
    remediationCommand: 'Create an EncryptionConfiguration with an aescbc or kms provider and set --encryption-provider-config=/etc/kubernetes/enc/enc.yaml on the API server.',
    impact: 'Existing Secrets must be rewritten (kubectl get secrets -A -o json | kubectl replace -f -) to be encrypted after enabling.',
    scored: true,
  },
  {
    id: '1.3.2',
    category: 'Control Plane',
    title: 'Ensure --profiling is set to false on the controller manager',
    description:
      'As with the API server, the controller manager\'s profiling endpoint should be disabled ' +
      'in production to reduce information disclosure and attack surface.',
    auditCommand: 'ps -ef | grep kube-controller-manager | grep -- "--profiling"',
    remediationCommand: '--profiling=false',
    impact: 'Reduces available debugging data; use dedicated staging environments for profiling instead.',
    scored: true,
  },
  {
    id: '1.3.6',
    category: 'Control Plane',
    title: 'Ensure --use-service-account-credentials is set to true on the controller manager',
    description:
      'This ensures individual controllers use their own distinct, narrowly scoped service ' +
      'account credentials rather than the shared controller-manager credential, limiting blast ' +
      'radius if one controller is compromised.',
    auditCommand: 'ps -ef | grep kube-controller-manager | grep -- "--use-service-account-credentials"',
    remediationCommand: '--use-service-account-credentials=true',
    impact: 'None significant; this is the recommended default configuration.',
    scored: true,
  },
  {
    id: '1.4.1',
    category: 'Control Plane',
    title: 'Ensure --profiling is set to false on the scheduler',
    description:
      'Disabling profiling on the scheduler component reduces attack surface consistent with ' +
      'the other control-plane components.',
    auditCommand: 'ps -ef | grep kube-scheduler | grep -- "--profiling"',
    remediationCommand: '--profiling=false',
    impact: 'Reduces available scheduler debugging data in production.',
    scored: true,
  },
  {
    id: '2.1',
    category: 'Control Plane',
    title: 'Ensure --cert-file and --key-file are set for etcd client connections',
    description:
      'etcd should require TLS for client connections so that data in transit (including ' +
      'Secrets) cannot be intercepted or tampered with on the network.',
    auditCommand: 'ps -ef | grep etcd | grep -- "--cert-file" ',
    remediationCommand: '--cert-file=/etc/kubernetes/pki/etcd/server.crt --key-file=/etc/kubernetes/pki/etcd/server.key',
    impact: 'Clients connecting to etcd must present valid certificates.',
    scored: true,
  },
  {
    id: '2.2',
    category: 'Control Plane',
    title: 'Ensure --client-cert-auth is set to true for etcd',
    description:
      'Requiring client certificate authentication for etcd prevents unauthenticated access to ' +
      'the entire cluster state store, which would otherwise bypass Kubernetes RBAC entirely.',
    auditCommand: 'ps -ef | grep etcd | grep -- "--client-cert-auth"',
    remediationCommand: '--client-cert-auth=true',
    impact: 'All etcd clients (primarily the API server) must be issued valid client certificates.',
    scored: true,
  },
  {
    id: '2.6',
    category: 'Control Plane',
    title: 'Ensure --peer-auto-tls is set to false for etcd',
    description:
      'Auto-generated, self-signed peer certificates are not properly validated by other etcd ' +
      'members, undermining the peer-to-peer TLS trust model and allowing rogue nodes to join the ' +
      'etcd cluster.',
    auditCommand: 'ps -ef | grep etcd | grep -- "--peer-auto-tls"',
    remediationCommand: '--peer-auto-tls=false and supply properly signed peer certificates via --peer-cert-file/--peer-key-file.',
    impact: 'Requires proper certificate issuance for every etcd peer.',
    scored: true,
  },

  // --- Worker Nodes --------------------------------------------------------
  {
    id: '4.1.1',
    category: 'Worker Nodes',
    title: 'Ensure the kubelet service file permissions are set to 600 or more restrictive',
    description:
      'Restricting permissions on the kubelet systemd unit file prevents unauthorized local ' +
      'users from modifying kubelet startup flags.',
    auditCommand: 'stat -c %a /etc/systemd/system/kubelet.service.d/10-kubeadm.conf',
    remediationCommand: 'chmod 600 /etc/systemd/system/kubelet.service.d/10-kubeadm.conf',
    impact: 'None.',
    scored: true,
  },
  {
    id: '4.2.1',
    category: 'Worker Nodes',
    title: 'Ensure --anonymous-auth is set to false on the kubelet',
    description:
      'Anonymous requests to the kubelet API allow unauthenticated actors to list pods and, ' +
      'depending on authorization mode, execute commands in containers on that node.',
    auditCommand: 'curl -sk https://localhost:10250/pods; or check /var/lib/kubelet/config.yaml for authentication.anonymous.enabled',
    remediationCommand: 'Set authentication.anonymous.enabled: false in the kubelet config file (/var/lib/kubelet/config.yaml) and restart kubelet.',
    impact: 'Any tooling relying on unauthenticated kubelet API calls must be updated to authenticate.',
    scored: true,
  },
  {
    id: '4.2.2',
    category: 'Worker Nodes',
    title: 'Ensure --authorization-mode is not set to AlwaysAllow on the kubelet',
    description:
      'AlwaysAllow authorization bypasses all access checks on the kubelet API, meaning any ' +
      'client that can reach the port can perform any kubelet operation, including exec into pods.',
    auditCommand: 'grep authorization /var/lib/kubelet/config.yaml',
    remediationCommand: 'Set authorization.mode: Webhook in the kubelet config so the API server is consulted for authorization decisions.',
    impact: 'Requires the API server to be reachable from the kubelet for authorization checks.',
    scored: true,
  },
  {
    id: '4.2.3',
    category: 'Worker Nodes',
    title: 'Ensure --client-ca-file is set appropriately on the kubelet',
    description:
      'Configuring a client CA file lets the kubelet validate client certificates presented by ' +
      'the API server, ensuring only trusted control-plane components can invoke kubelet actions.',
    auditCommand: 'grep clientCAFile /var/lib/kubelet/config.yaml',
    remediationCommand: 'authentication.x509.clientCAFile: /etc/kubernetes/pki/ca.crt',
    impact: 'None beyond proper certificate provisioning already required for cluster operation.',
    scored: true,
  },
  {
    id: '4.2.6',
    category: 'Worker Nodes',
    title: 'Ensure --protect-kernel-defaults is set to true on the kubelet',
    description:
      'This flag causes the kubelet to error out (rather than silently override) if kernel ' +
      'parameters it depends on for security have been changed from expected values, catching ' +
      'accidental or malicious kernel tuning drift.',
    auditCommand: 'grep protectKernelDefaults /var/lib/kubelet/config.yaml',
    remediationCommand: 'protectKernelDefaults: true',
    impact: 'Kubelet will fail to start if underlying kernel parameters do not match expectations, requiring the host image to be corrected.',
    scored: true,
  },
  {
    id: '4.2.10',
    category: 'Worker Nodes',
    title: 'Ensure kubelet certificate rotation is enabled',
    description:
      'Automatic client and server certificate rotation (RotateKubeletServerCertificate / ' +
      'RotateKubeletClientCertificate) reduces the operational burden of certificate expiry and ' +
      'limits the lifetime of any single compromised kubelet certificate.',
    auditCommand: 'grep -E "rotateCertificates|serverTLSBootstrap" /var/lib/kubelet/config.yaml',
    remediationCommand: 'rotateCertificates: true and serverTLSBootstrap: true, then approve the resulting CertificateSigningRequests.',
    impact: 'Requires a process (manual or automated via kubelet-csr-approver) to approve rotated CSRs.',
    scored: true,
  },
  {
    id: '4.2.12',
    category: 'Worker Nodes',
    title: 'Ensure a limited set of TLS cipher suites is used on the kubelet',
    description:
      'Restricting the kubelet to strong, modern cipher suites prevents downgrade attacks and ' +
      'reduces the risk of exploitation via weak cryptography.',
    auditCommand: 'grep tlsCipherSuites /var/lib/kubelet/config.yaml',
    remediationCommand: 'tlsCipherSuites: ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]',
    impact: 'Older clients that only support weak/legacy ciphers will fail to connect.',
    scored: false,
  },

  // --- Policies (RBAC and Pod Security) -----------------------------------
  {
    id: '5.1.1',
    category: 'Policies',
    title: 'Ensure cluster-admin role is only used where required',
    description:
      'The built-in cluster-admin ClusterRole grants unrestricted access to every resource in ' +
      'every namespace; binding it broadly (e.g. to the default service account or many users) ' +
      'violates least privilege and dramatically increases blast radius from any single ' +
      'compromised identity.',
    auditCommand: 'kubectl get clusterrolebindings -o json | jq \'.items[] | select(.roleRef.name=="cluster-admin")\'',
    remediationCommand: 'Remove unnecessary ClusterRoleBindings to cluster-admin; create scoped Roles/ClusterRoles for specific job functions instead.',
    impact: 'Users/service accounts previously relying on implicit broad access must be granted explicit, narrower roles.',
    scored: false,
  },
  {
    id: '5.1.3',
    category: 'Policies',
    title: 'Minimize wildcard use in Roles and ClusterRoles',
    description:
      'Roles using verbs: ["*"] or resources: ["*"] grant far more access than most workloads ' +
      'need and make it difficult to reason about the actual permissions a service account holds.',
    auditCommand: 'kubectl get roles,clusterroles -A -o json | jq \'.items[] | select(.rules[]?.resources[]? == "*" or .rules[]?.verbs[]? == "*")\'',
    remediationCommand: 'Replace wildcards with the explicit, minimal set of verbs and resources each role actually requires, derived using tools like audit2rbac.',
    impact: 'Requires ongoing maintenance as workloads evolve and need new permissions granted explicitly.',
    scored: false,
  },
  {
    id: '5.1.5',
    category: 'Policies',
    title: 'Ensure default service accounts are not actively used',
    description:
      'The automatically created "default" service account in every namespace should not be ' +
      'granted any permissions and should not be assigned to workloads; pods should use ' +
      'dedicated, purpose-specific service accounts.',
    auditCommand: 'kubectl get pods -A -o jsonpath="{range .items[?(@.spec.serviceAccountName==\\"default\\")]}{.metadata.namespace}/{.metadata.name}{\\"\\n\\"}{end}"',
    remediationCommand: 'Set automountServiceAccountToken: false on the default ServiceAccount in every namespace, and create dedicated service accounts per workload.',
    impact: 'Requires explicitly creating and assigning a service account for every workload going forward.',
    scored: false,
  },
  {
    id: '5.1.6',
    category: 'Policies',
    title: 'Ensure service account tokens are only mounted where necessary',
    description:
      'automountServiceAccountToken should be false for any pod that does not need to call the ' +
      'Kubernetes API, minimizing the number of workloads carrying a bearer token an attacker ' +
      'could steal.',
    auditCommand: 'kubectl get pods -A -o jsonpath="{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.spec.automountServiceAccountToken}{\\"\\n\\"}{end}"',
    remediationCommand: 'Set automountServiceAccountToken: false in the PodSpec or ServiceAccount for workloads with no need to call the API server.',
    impact: 'Workloads that later need API access must explicitly opt back in.',
    scored: false,
  },
  {
    id: '5.2.2',
    category: 'Policies',
    title: 'Minimize the admission of privileged containers',
    description:
      'Enforcing the Pod Security Standard "restricted" (or an equivalent OPA/Kyverno policy) at ' +
      'the namespace level blocks pods that request securityContext.privileged: true, closing off ' +
      'one of the most direct container-escape vectors.',
    auditCommand: 'kubectl get ns -o json | jq \'.items[].metadata.labels["pod-security.kubernetes.io/enforce"]\'',
    remediationCommand: 'kubectl label ns <namespace> pod-security.kubernetes.io/enforce=restricted --overwrite',
    impact: 'Legitimate workloads that genuinely require privileged mode (rare, e.g. certain CNI/storage daemonsets) must be placed in an explicitly exempted, tightly controlled namespace.',
    scored: true,
  },
  {
    id: '5.2.4',
    category: 'Policies',
    title: 'Minimize the admission of containers wishing to share the host process ID namespace',
    description:
      'hostPID: true lets a container see and interact with all processes on the host, ' +
      'undermining process isolation.',
    auditCommand: 'kubectl get pods -A -o jsonpath="{range .items[?(@.spec.hostPID==true)]}{.metadata.namespace}/{.metadata.name}{\\"\\n\\"}{end}"',
    remediationCommand: 'Enforce Pod Security "restricted" or a Kyverno/OPA policy disallowing hostPID: true.',
    impact: 'Legacy debugging workloads relying on hostPID must be redesigned or isolated.',
    scored: true,
  },
  {
    id: '5.2.5',
    category: 'Policies',
    title: 'Minimize the admission of containers wishing to share the host network namespace',
    description:
      'hostNetwork: true removes network namespace isolation, letting the container bind any ' +
      'host port and observe host network traffic.',
    auditCommand: 'kubectl get pods -A -o jsonpath="{range .items[?(@.spec.hostNetwork==true)]}{.metadata.namespace}/{.metadata.name}{\\"\\n\\"}{end}"',
    remediationCommand: 'Enforce Pod Security "restricted" or an equivalent admission policy disallowing hostNetwork: true.',
    impact: 'Workloads needing specific host ports must use hostPort or a properly published Service/Ingress instead.',
    scored: true,
  },
  {
    id: '5.2.6',
    category: 'Policies',
    title: 'Minimize the admission of containers with allowPrivilegeEscalation',
    description:
      'allowPrivilegeEscalation: true (the default if unset) permits a process to gain more ' +
      'privileges than its parent, for example via setuid binaries, undermining the intended ' +
      'privilege boundary of the container.',
    auditCommand: 'kubectl get pods -A -o json | jq \'.items[].spec.containers[] | select(.securityContext.allowPrivilegeEscalation != false)\'',
    remediationCommand: 'Set securityContext.allowPrivilegeEscalation: false on every container; enforce cluster-wide via Pod Security "restricted".',
    impact: 'Applications relying on setuid binaries for legitimate privilege changes must be redesigned.',
    scored: true,
  },
  {
    id: '5.2.7',
    category: 'Policies',
    title: 'Minimize the admission of root containers',
    description:
      'Requiring runAsNonRoot: true (and ideally a specific runAsUser) ensures container ' +
      'processes never run as UID 0, reducing the impact of a container-escape vulnerability.',
    auditCommand: 'kubectl get pods -A -o json | jq \'.items[].spec.securityContext.runAsNonRoot\'',
    remediationCommand: 'Set securityContext.runAsNonRoot: true and runAsUser: <non-zero-uid> at the pod or container level; enforce via Pod Security "restricted".',
    impact: 'Images that hard-code root execution (no USER instruction) must be rebuilt with a dedicated unprivileged user.',
    scored: true,
  },
  {
    id: '5.2.9',
    category: 'Policies',
    title: 'Minimize the admission of containers with capabilities beyond the default set',
    description:
      'Any capability added beyond Docker/Kubernetes\' minimal default set should be explicitly ' +
      'justified; NET_RAW and others in the default set should also be dropped where unused.',
    auditCommand: 'kubectl get pods -A -o json | jq \'.items[].spec.containers[].securityContext.capabilities.add\'',
    remediationCommand: 'securityContext.capabilities: {drop: ["ALL"], add: [<only what is required>]}',
    impact: 'Applications must be tested to confirm they function correctly with capabilities dropped.',
    scored: true,
  },
  {
    id: '5.3.2',
    category: 'Network',
    title: 'Ensure that all Namespaces have Network Policies defined',
    description:
      'Without a NetworkPolicy, all pod-to-pod traffic in a namespace is allowed by default; ' +
      'every namespace should have at least a default-deny policy with explicit allow rules layered ' +
      'on top.',
    auditCommand: 'kubectl get networkpolicy -A',
    remediationCommand: 'Apply a default-deny-all NetworkPolicy to every namespace, then add specific allow rules (see K8S_NETWORK_POLICIES).',
    impact: 'Requires mapping legitimate traffic flows per application to avoid breaking connectivity when default-deny is introduced.',
    scored: false,
  },

  // --- Secrets ---------------------------------------------------------------
  {
    id: '5.4.1',
    category: 'Secrets',
    title: 'Prefer using Secrets as files over Secrets as environment variables',
    description:
      'Secrets exposed as environment variables are more likely to be inadvertently leaked via ' +
      'process listings, crash dumps, child-process environment inheritance, and logging than ' +
      'Secrets mounted as files.',
    auditCommand: 'kubectl get pods -A -o json | jq \'.items[].spec.containers[].env[]? | select(.valueFrom.secretKeyRef)\'',
    remediationCommand: 'Mount Secrets as volumes (volumeMounts referencing a secret volume) instead of using envFrom/valueFrom.secretKeyRef.',
    impact: 'Application code must be updated to read configuration from mounted files instead of environment variables.',
    scored: false,
  },
  {
    id: '5.4.2',
    category: 'Secrets',
    title: 'Consider external secret storage',
    description:
      'Native Kubernetes Secrets provide only base64 encoding without encryption unless ' +
      'EncryptionConfiguration is enabled, and lack fine-grained access auditing; an external ' +
      'secret manager (Vault, AWS/GCP/Azure secret services) provides encryption, versioning, ' +
      'auditing, and automatic rotation.',
    auditCommand: 'Review whether Secrets are sourced natively or synced from an external manager (e.g. via External Secrets Operator CRDs).',
    remediationCommand: 'Deploy the External Secrets Operator or Vault CSI Provider and migrate sensitive values to the external store, referencing them via ExternalSecret CRDs.',
    impact: 'Adds an operational dependency on the external secrets backend and requires migration effort.',
    scored: false,
  },

  // --- Logging -----------------------------------------------------------
  {
    id: '3.2.1',
    category: 'Logging',
    title: 'Ensure that a minimal audit policy is created and enabled',
    description:
      'A defined --audit-policy-file controls which requests are logged and at what detail ' +
      'level, forming the baseline for detecting suspicious API activity.',
    auditCommand: 'ps -ef | grep kube-apiserver | grep -- "--audit-policy-file"',
    remediationCommand: 'Create /etc/kubernetes/audit-policy.yaml defining rules for Metadata/Request/RequestResponse levels and set --audit-policy-file on the API server.',
    impact: 'Additional storage and processing overhead for audit log volume.',
    scored: true,
  },
  {
    id: '3.2.2',
    category: 'Logging',
    title: 'Ensure that the audit policy covers key security concerns',
    description:
      'The audit policy should specifically capture Secret access, RBAC changes, exec/attach ' +
      'requests, and authentication failures at a sufficient detail level (Request or ' +
      'RequestResponse) to support incident investigation.',
    auditCommand: 'Review /etc/kubernetes/audit-policy.yaml for rules covering secrets, rbac.authorization.k8s.io, and pods/exec.',
    remediationCommand: 'Add explicit audit rules, e.g. a rule at level RequestResponse for resources: ["secrets"] and for the pods/exec, pods/attach subresources.',
    impact: 'Higher log volume for high-value events; ensure log storage and SIEM ingestion is sized accordingly.',
    scored: false,
  },
  {
    id: '3.2.3',
    category: 'Logging',
    title: 'Forward audit and control-plane logs to a centralized, tamper-evident log store',
    description:
      'Logs retained only on control-plane node disks can be lost, rotated out, or deleted by an ' +
      'attacker who gains node access, destroying forensic evidence of the attack.',
    auditCommand: 'Verify a log shipping agent (Fluent Bit, Fluentd, or cloud-native log agent) is deployed as a DaemonSet and configured to forward audit logs off-cluster.',
    remediationCommand: 'Deploy a Fluent Bit DaemonSet mounting /var/log/kubernetes/audit and forward to a SIEM/immutable log store (e.g. an object storage bucket with object-lock/WORM enabled).',
    impact: 'Additional infrastructure and cost for centralized log storage and ingestion.',
    scored: false,
  },
  {
    id: '4.2.13',
    category: 'Logging',
    title: 'Enable Seccomp for the kubelet and cluster-wide',
    description:
      'Setting a RuntimeDefault seccomp profile cluster-wide reduces the syscall surface ' +
      'available to every container without requiring per-workload configuration.',
    auditCommand: 'kubectl get pods -A -o json | jq \'.items[].spec.securityContext.seccompProfile.type\'',
    remediationCommand: 'Set seccompDefault: true in the kubelet configuration (or securityContext.seccompProfile.type: RuntimeDefault per pod).',
    impact: 'Rare workloads requiring unusual syscalls may need a custom, explicitly reviewed seccomp profile.',
    scored: false,
  },
];

// =============================================================================
// 4. CONTAINER_TOOLS
// =============================================================================

const CONTAINER_TOOLS = [

  {
    name: 'Trivy',
    type: 'scanner',
    description:
      'Open-source, comprehensive vulnerability and misconfiguration scanner from Aqua Security. ' +
      'Scans container images, filesystems, git repositories, Kubernetes clusters, and IaC ' +
      'templates for OS package CVEs, language-specific dependency CVEs, embedded secrets, and ' +
      'misconfigurations, all from a single fast binary with no external database dependency.',
    install: 'brew install aquasecurity/trivy/trivy   # or: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin',
    usage: 'trivy image --severity HIGH,CRITICAL myapp:latest',
    features: [
      'OS package and language dependency (npm, pip, go.mod, gem, maven) CVE scanning',
      'Dockerfile, Kubernetes manifest, Terraform, and CloudFormation misconfiguration scanning',
      'Secret detection (API keys, tokens, private keys) embedded in image layers',
      'SBOM generation and consumption (CycloneDX, SPDX)',
      'Kubernetes cluster scanning via "trivy k8s"',
      'CI/CD integration with configurable exit codes for pipeline gating',
    ],
  },
  {
    name: 'Grype',
    type: 'scanner',
    description:
      'Anchore\'s fast, open-source vulnerability scanner for container images and filesystems, ' +
      'commonly paired with Syft for SBOM generation. Uses a locally cached vulnerability ' +
      'database updated from multiple upstream feeds (NVD, GitHub Security Advisories, distro ' +
      'security trackers).',
    install: 'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin',
    usage: 'grype myapp:latest --fail-on high',
    features: [
      'CVE matching against a locally cached, regularly updated vulnerability database',
      'Consumes Syft-generated SBOMs directly for faster repeated scans',
      'Supports scanning images, directories, and archives',
      'Configurable severity thresholds for CI/CD gating (--fail-on)',
      'JSON, table, SARIF, and CycloneDX output formats for tool integration',
    ],
  },
  {
    name: 'Syft',
    type: 'scanner',
    description:
      'Anchore\'s Software Bill of Materials (SBOM) generation tool. Inspects container images ' +
      'and filesystems to produce a complete inventory of packages and dependencies, which can be ' +
      'fed into Grype or other vulnerability matchers and used for supply-chain provenance and ' +
      'compliance.',
    install: 'curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin',
    usage: 'syft myapp:latest -o cyclonedx-json=sbom.json',
    features: [
      'Detects packages across dozens of ecosystems (apk, deb, rpm, npm, pip, gem, cargo, go modules, jar)',
      'Multiple SBOM output formats: SPDX, CycloneDX, Syft native JSON',
      'Attaches SBOMs to OCI images as attestations (with cosign) for supply-chain verification',
      'Can scan running containers, image archives, or plain directories',
    ],
  },
  {
    name: 'Falco',
    type: 'runtime',
    description:
      'CNCF graduated open-source runtime security tool originally created by Sysdig. Falco taps ' +
      'into kernel syscalls (via eBPF or a kernel module) and Kubernetes audit events to detect ' +
      'anomalous behavior in real time, such as shells spawned in containers, unexpected outbound ' +
      'connections, or privilege escalation attempts, based on a rich, customizable rule set.',
    install: 'curl -fsSL https://falco.org/repo/falcosecurity-3672BA8F.asc | sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg && sudo apt-get install falco',
    usage: 'falco --pidns  -r /etc/falco/falco_rules.yaml   # or deploy via the official falco Helm chart in Kubernetes',
    features: [
      'eBPF-based syscall monitoring with minimal performance overhead',
      'Prebuilt rule sets for container escape, privilege escalation, and crypto-mining detection',
      'Kubernetes audit log integration (Falcosidekick) for API-level anomaly detection',
      'Real-time alerting to Slack, PagerDuty, SIEM, or a webhook via Falcosidekick',
      'Custom rule authoring in a human-readable YAML DSL',
    ],
  },
  {
    name: 'kube-bench',
    type: 'audit',
    description:
      'Aqua Security\'s open-source tool that checks whether a Kubernetes cluster is deployed ' +
      'according to the CIS Kubernetes Benchmark, running the actual audit commands for each ' +
      'benchmark control against the live cluster nodes and reporting PASS/FAIL/WARN.',
    install: 'docker pull aquasec/kube-bench:latest   # or download a release binary from github.com/aquasecurity/kube-bench',
    usage: 'kube-bench run --targets master,node,etcd,policies',
    features: [
      'Implements CIS Kubernetes Benchmark checks version-matched to the cluster (kubeadm, EKS, GKE, OpenShift variants)',
      'Runs as a Job/DaemonSet across control-plane and worker nodes',
      'JSON output for CI pipeline integration and trend tracking',
      'Node-type auto-detection (master vs. worker) via --benchmark or auto-detection logic',
    ],
  },
  {
    name: 'kube-hunter',
    type: 'audit',
    description:
      'Aqua Security\'s open-source penetration-testing tool for Kubernetes clusters. Actively ' +
      'probes for known attack vectors such as exposed dashboards, anonymous kubelet access, and ' +
      'exposed etcd, simulating what an external or in-cluster attacker would discover during ' +
      'reconnaissance.',
    install: 'pip install kube-hunter   # or: docker run -it --rm --network host aquasec/kube-hunter',
    usage: 'kube-hunter --remote <cluster-ip>   # or --pod for in-cluster active hunting mode',
    features: [
      'Remote, internal (pod-based), and network-scan hunting modes',
      'Detects exposed dashboards, kubelet APIs, etcd, and known CVE-affected component versions',
      'Active exploitation modules (--active) that attempt to prove exploitability, not just detect exposure',
      'Reports findings mapped to specific vulnerability classes with remediation guidance',
    ],
  },
  {
    name: 'kubeaudit',
    type: 'audit',
    description:
      'Open-source command-line tool (originally from Shopify) that audits Kubernetes clusters ' +
      'for common security misconfigurations at the manifest/API level, such as containers ' +
      'running as root, missing resource limits, and dangerous capabilities.',
    install: 'go install github.com/Shopify/kubeaudit@latest',
    usage: 'kubeaudit all -f deployment.yaml   # or run against a live cluster: kubeaudit all',
    features: [
      'Checks for non-root enforcement, capabilities, privilege escalation, read-only root filesystem, and more',
      'Can audit local manifest files or a live cluster via the current kubeconfig context',
      'Autofix mode (kubeaudit autofix) that rewrites manifests to remediate common findings',
      'Machine-readable JSON/logrus output for CI integration',
    ],
  },
  {
    name: 'Checkov',
    type: 'audit',
    description:
      'Bridgecrew/Prisma Cloud\'s open-source static analysis tool for Infrastructure as Code, ' +
      'including Dockerfiles, Kubernetes manifests, Helm charts, Terraform, and CloudFormation, ' +
      'checking them against hundreds of built-in security and compliance policies before ' +
      'deployment.',
    install: 'pip install checkov',
    usage: 'checkov -f Dockerfile   # or: checkov -d ./k8s-manifests --framework kubernetes',
    features: [
      'Hundreds of built-in policies covering Docker, Kubernetes, Terraform, CloudFormation, ARM, Helm',
      'Custom policy authoring in Python or a YAML-based policy DSL',
      'SARIF/JUnit output for CI pipeline and code-review integration',
      'Suppression annotations for accepted-risk findings with documented justification',
    ],
  },
  {
    name: 'Terrascan',
    type: 'audit',
    description:
      'Open-source static analysis tool for Infrastructure as Code from Tenable, detecting ' +
      'compliance and security violations across Terraform, Kubernetes, Helm, and Kustomize using ' +
      'the Open Policy Agent (OPA) Rego policy engine.',
    install: 'curl -L "$(curl -s https://api.github.com/repos/tenable/terrascan/releases/latest | grep -o -E "https://.+?_Linux_x86_64.tar.gz")" > terrascan.tar.gz && tar -xf terrascan.tar.gz terrascan && install terrascan /usr/local/bin',
    usage: 'terrascan scan -i k8s -d ./manifests',
    features: [
      'Rego-based policy engine allowing fully custom organizational policy authoring',
      'Built-in policy library mapped to CIS benchmarks and best practices',
      'Supports Terraform, Kubernetes, Helm, Kustomize, and Dockerfile scanning',
      'Admission-controller webhook mode for real-time cluster enforcement',
    ],
  },
  {
    name: 'Snyk Container',
    type: 'scanner',
    description:
      'Commercial (with free tier) developer-first vulnerability scanner for container images, ' +
      'integrating directly into IDEs, CI/CD, and registries. Correlates base-image CVEs with ' +
      'application dependency CVEs and suggests the minimal base-image upgrade path to remediate.',
    install: 'npm install -g snyk',
    usage: 'snyk container test myapp:latest --file=Dockerfile',
    features: [
      'Base-image upgrade recommendations that minimize the number of new CVEs introduced',
      'Continuous registry monitoring with alerting on newly disclosed CVEs for already-deployed images',
      'Dockerfile best-practice linting alongside vulnerability scanning',
      'IDE and Git PR integrations for shift-left remediation',
    ],
  },
  {
    name: 'Aqua Security (Aqua Platform)',
    type: 'runtime',
    description:
      'Commercial end-to-end cloud native application protection platform (CNAPP) covering image ' +
      'scanning, runtime protection, Kubernetes posture management, and compliance reporting, ' +
      'built in part on the open-source Trivy scanning engine.',
    install: 'Deployed via Helm chart provided under an Aqua Security commercial license: helm install aqua aqua/aqua-console',
    usage: 'Configured via the Aqua Console UI/API to enforce image assurance policies at the registry, CI, and admission-controller layers.',
    features: [
      'Runtime drift prevention (blocking processes/files not present in the original image)',
      'Kubernetes admission control enforcing image assurance policies',
      'Cloud Security Posture Management (CSPM) across AWS/Azure/GCP',
      'Micro-segmentation and network-based runtime protection',
    ],
  },
  {
    name: 'Prisma Cloud (Palo Alto Networks)',
    type: 'runtime',
    description:
      'Commercial CNAPP providing container image scanning, Kubernetes CIS benchmark compliance, ' +
      'runtime defense, and cloud infrastructure posture management in a single platform, widely ' +
      'used in large enterprise Kubernetes fleets.',
    install: 'Deployed via the twistcli CLI and the Prisma Cloud Defender DaemonSet, provisioned under a commercial license.',
    usage: 'twistcli images scan --address <console-url> myapp:latest',
    features: [
      'Automated CIS Kubernetes Benchmark compliance reporting across the fleet',
      'Runtime process/network/file-integrity monitoring via the Defender agent',
      'IaC scanning integrated into CI/CD (Terraform, CloudFormation, Kubernetes manifests)',
      'Web-application and API security (WAAS) module for ingress-layer protection',
    ],
  },
  {
    name: 'Anchore Enterprise',
    type: 'scanner',
    description:
      'Commercial platform built around the open-source Syft/Grype engines, adding policy ' +
      'enforcement, SBOM management at scale, and compliance reporting (FedRAMP, SSDF) for ' +
      'organizations with strict supply-chain assurance requirements.',
    install: 'Deployed via Helm chart under a commercial license: helm install anchore anchore/anchore-engine',
    usage: 'anchorectl image add myapp:latest && anchorectl image vuln myapp:latest',
    features: [
      'Centralized SBOM inventory and vulnerability policy enforcement across all scanned images',
      'Policy bundles mapping to compliance frameworks (NIST SSDF, FedRAMP)',
      'Integration with CI/CD and registries for automated gating on image push',
      'Historical vulnerability trend reporting across the image fleet',
    ],
  },
  {
    name: 'Clair',
    type: 'scanner',
    description:
      'CoreOS/Quay\'s open-source, API-driven static vulnerability analysis engine for container ' +
      'images, commonly used as the scanning backend embedded in the Quay and Harbor container ' +
      'registries.',
    install: 'docker run -d -p 6060:6060 -p 6061:6061 quay.io/projectquay/clair:4.7',
    usage: 'clairctl report myapp:latest   # or trigger scans via the Clair API from an integrated registry',
    features: [
      'API-first design meant to be embedded in registries and CI systems rather than run standalone',
      'Layer-by-layer CVE analysis correlated against multiple upstream vulnerability feeds',
      'Native integration with Harbor and Quay registries for scan-on-push',
      'Notification webhooks when a previously-clean image is later found vulnerable',
    ],
  },
  {
    name: 'Docker Bench for Security',
    type: 'audit',
    description:
      'Docker, Inc.\'s open-source shell script that checks a running Docker host and its ' +
      'containers against the CIS Docker Benchmark, directly implementing the audit commands for ' +
      'each control.',
    install: 'git clone https://github.com/docker/docker-bench-security.git && cd docker-bench-security',
    usage: 'sudo sh docker-bench-security.sh',
    features: [
      'Direct implementation of CIS Docker Benchmark checks (host config, daemon config, image/container runtime config)',
      'Runs as a lightweight shell script or as a container with appropriate host mounts',
      'Human-readable PASS/WARN/INFO output with the exact rationale for each check',
      'No external dependencies beyond a POSIX shell and standard Linux utilities',
    ],
  },
  {
    name: 'Kyverno',
    type: 'audit',
    description:
      'CNCF Kubernetes-native policy engine that validates, mutates, and generates resources ' +
      'using policies written in plain YAML (no separate DSL like Rego), commonly used as an ' +
      'admission controller to enforce Pod Security, image signature verification, and custom ' +
      'organizational rules.',
    install: 'helm install kyverno kyverno/kyverno -n kyverno --create-namespace',
    usage: 'kubectl apply -f disallow-privileged-containers.yaml   # a Kyverno ClusterPolicy',
    features: [
      'Validating, mutating, and resource-generating policies written natively in Kubernetes YAML',
      'Built-in policy library covering Pod Security Standards and common CIS controls',
      'Image signature and SBOM attestation verification (verifyImages) integrating with cosign/Sigstore',
      'Policy reports (PolicyReport CRDs) for continuous compliance visibility',
    ],
  },
  {
    name: 'OPA Gatekeeper',
    type: 'audit',
    description:
      'CNCF project pairing Open Policy Agent with a Kubernetes admission-controller webhook, ' +
      'letting organizations author custom policy-as-code in Rego (ConstraintTemplates) to ' +
      'validate or reject resources at admission time.',
    install: 'kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml',
    usage: 'kubectl apply -f constrainttemplate.yaml && kubectl apply -f constraint.yaml',
    features: [
      'Rego-based ConstraintTemplates offering highly flexible, composable policy logic',
      'Audit mode reporting existing non-compliant resources without blocking, alongside enforcement mode',
      'Library of community constraint templates (gatekeeper-library) for common CIS-style controls',
      'Dry-run and exempt-namespace support for safe, incremental policy rollout',
    ],
  },
];

// =============================================================================
// 5. DOCKERFILE_BEST_PRACTICES
// =============================================================================

const DOCKERFILE_BEST_PRACTICES = [

  {
    practice: 'Pin the base image to a specific, minimal, digest-verified tag',
    description:
      'Floating tags such as "latest" or even a bare major version resolve to different content ' +
      'over time, breaking build reproducibility and silently pulling in new CVEs.',
    badExample: 'FROM node:latest',
    goodExample: 'FROM node:20.11.1-alpine3.19@sha256:3f8a1c9e6d2b...',
    reason: 'Digest pinning guarantees byte-for-byte reproducible builds and prevents an upstream tag mutation from silently changing what gets deployed.',
  },
  {
    practice: 'Run as a non-root user',
    description:
      'Without an explicit USER instruction, the container process runs as root (UID 0) inside ' +
      'the container, widening the impact of any code-execution vulnerability in the app.',
    badExample:
      'FROM python:3.12-slim\n' +
      'COPY . /app\n' +
      'WORKDIR /app\n' +
      'CMD ["python", "app.py"]',
    goodExample:
      'FROM python:3.12-slim\n' +
      'RUN groupadd -r app && useradd -r -g app -u 1001 app\n' +
      'COPY --chown=app:app . /app\n' +
      'WORKDIR /app\n' +
      'USER app\n' +
      'CMD ["python", "app.py"]',
    reason: 'Running as a dedicated unprivileged user limits what an attacker with code execution can do inside the container and satisfies CIS Docker Benchmark 4.1.',
  },
  {
    practice: 'Never embed secrets with ENV, ARG, or COPY',
    description:
      'Secrets baked into any layer remain recoverable via "docker history" or by unpacking the ' +
      'image, even if a later layer deletes the file.',
    badExample:
      'FROM alpine\n' +
      'ARG NPM_TOKEN\n' +
      'ENV NPM_TOKEN=${NPM_TOKEN}\n' +
      'RUN npm install',
    goodExample:
      '# syntax=docker/dockerfile:1\n' +
      'FROM alpine\n' +
      'RUN --mount=type=secret,id=npm_token \\\n' +
      '    NPM_TOKEN=$(cat /run/secrets/npm_token) npm install',
    reason: 'BuildKit secret mounts expose the value only to the single RUN step and never persist it in any image layer.',
  },
  {
    practice: 'Use multi-stage builds to exclude build tools from the final image',
    description:
      'Compilers, build caches, and dev dependencies bundled into the runtime image increase ' +
      'attack surface and image size without providing any runtime value.',
    badExample:
      'FROM golang:1.22\n' +
      'WORKDIR /src\n' +
      'COPY . .\n' +
      'RUN go build -o app .\n' +
      'CMD ["./app"]',
    goodExample:
      'FROM golang:1.22 AS build\n' +
      'WORKDIR /src\n' +
      'COPY . .\n' +
      'RUN CGO_ENABLED=0 go build -o /app .\n' +
      '\n' +
      'FROM gcr.io/distroless/static-debian12\n' +
      'COPY --from=build /app /app\n' +
      'USER nonroot:nonroot\n' +
      'ENTRYPOINT ["/app"]',
    reason: 'The final image ships only the compiled binary on a distroless base, eliminating the Go toolchain, shell, and package manager from the attack surface entirely.',
  },
  {
    practice: 'Use a read-only root filesystem at runtime',
    description:
      'A writable container filesystem lets an attacker persist a backdoor or tamper with ' +
      'application binaries after gaining code execution.',
    badExample: 'docker run myapp:1.0',
    goodExample:
      'docker run --read-only --tmpfs /tmp --tmpfs /var/run myapp:1.0\n' +
      '# and in Kubernetes: securityContext.readOnlyRootFilesystem: true',
    reason: 'Combined with explicit tmpfs mounts for the few paths that truly need write access, this prevents any persistent modification of the container filesystem.',
  },
  {
    practice: 'Drop all Linux capabilities and add back only what is required',
    description:
      'The Docker default capability set includes several capabilities (CAP_NET_RAW, ' +
      'CAP_SETUID, CAP_SETGID) that most applications never use.',
    badExample: 'docker run --cap-add=ALL myapp:1.0',
    goodExample: 'docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE myapp:1.0',
    reason: 'Minimizing capabilities closes off many published container-escape and local-privilege-escalation techniques that rely on a specific capability being present.',
  },
  {
    practice: 'Add a HEALTHCHECK instruction',
    description:
      'Without a health check, the orchestrator has no application-level signal that the ' +
      'service inside the container is actually functioning correctly.',
    badExample: 'CMD ["node", "server.js"]',
    goodExample:
      'HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\\n' +
      '  CMD wget --quiet --tries=1 --spider http://localhost:3000/healthz || exit 1\n' +
      'CMD ["node", "server.js"]',
    reason: 'A meaningful health check lets Docker/Kubernetes detect and automatically remediate a hung or compromised process, satisfying CIS Docker Benchmark 4.6.',
  },
  {
    practice: 'Minimize and pin installed OS packages, then clean up package-manager caches',
    description:
      'Installing unnecessary packages (curl, wget, netcat, compilers) in a production image ' +
      'increases the number of exploitable binaries available to an attacker post-compromise, ' +
      'and unpinned versions cause non-reproducible builds.',
    badExample:
      'RUN apt-get update && apt-get install -y curl wget vim netcat build-essential',
    goodExample:
      'RUN apt-get update && apt-get install -y --no-install-recommends \\\n' +
      '      libpq5=15.* \\\n' +
      '    && rm -rf /var/lib/apt/lists/*',
    reason: 'Pinning versions ensures reproducibility, --no-install-recommends avoids pulling in unnecessary transitive packages, and clearing apt lists reduces final image size and residual metadata.',
  },
  {
    practice: 'Use COPY instead of ADD unless remote-fetch/auto-extract behavior is specifically needed',
    description:
      'ADD has implicit behaviors (auto-extracting tarballs, fetching remote URLs) that are easy ' +
      'to misuse and can introduce unexpected or untrusted content into the image.',
    badExample: 'ADD https://example.com/app.tar.gz /app/',
    goodExample:
      'COPY app.tar.gz /tmp/\n' +
      'RUN tar -xzf /tmp/app.tar.gz -C /app && rm /tmp/app.tar.gz',
    reason: 'Explicit, auditable steps make it clear exactly what content enters the image and avoid ADD silently fetching from a URL that may later be compromised or unavailable.',
  },
  {
    practice: 'Order Dockerfile instructions to maximize build-cache reuse without hiding stale dependencies',
    description:
      'Placing frequently changing instructions (like COPY . .) before dependency installation ' +
      'invalidates the cache on every build, slowing CI and encouraging developers to skip re-scans.',
    badExample:
      'FROM node:20-alpine\n' +
      'WORKDIR /app\n' +
      'COPY . .\n' +
      'RUN npm install\n' +
      'CMD ["node", "index.js"]',
    goodExample:
      'FROM node:20-alpine\n' +
      'WORKDIR /app\n' +
      'COPY package.json package-lock.json ./\n' +
      'RUN npm ci --omit=dev\n' +
      'COPY . .\n' +
      'CMD ["node", "index.js"]',
    reason: 'Copying only the lockfile first lets Docker cache the dependency-install layer, so faster, more frequent rebuilds encourage keeping the image current with security patches.',
  },
  {
    practice: 'Avoid running package managers with unpinned "latest" semantics for dependencies',
    description:
      'Using unpinned dependency ranges in package.json/requirements.txt allows a compromised or ' +
      'malicious upstream package release to be pulled in automatically on the next build.',
    badExample: 'RUN pip install requests flask',
    goodExample: 'RUN pip install --require-hashes -r requirements.txt   # requirements.txt pins exact versions and hashes',
    reason: 'Hash-pinned, exact-version dependency installation prevents supply-chain attacks where a compromised package version is published to a public registry.',
  },
  {
    practice: 'Explicitly set WORKDIR instead of relying on RUN cd',
    description:
      'Using "RUN cd /app && ..." only changes directory for that single RUN layer and is a ' +
      'common source of confusing, hard-to-audit path bugs.',
    badExample: 'RUN cd /app && npm install',
    goodExample:
      'WORKDIR /app\n' +
      'RUN npm install',
    reason: 'WORKDIR persists the working directory for all subsequent instructions, making the Dockerfile easier to reason about and audit.',
  },
  {
    practice: 'Do not expose unnecessary ports',
    description:
      'Declaring EXPOSE for ports the application does not actually listen on, or that provide ' +
      'debugging/administrative interfaces, misleads operators about the container\'s network ' +
      'surface and can lead to accidental publication.',
    badExample: 'EXPOSE 22 80 443 3000 9229',
    goodExample: 'EXPOSE 3000',
    reason: 'Documenting only the actual application port (here, dropping a leftover Node.js debug port 9229 and an unused SSH port 22) keeps the declared attack surface accurate and minimal.',
  },
  {
    practice: 'Use .dockerignore to exclude sensitive and unnecessary files from the build context',
    description:
      'Without a .dockerignore, the entire build context (including .git, .env, node_modules, ' +
      'and credential files) is sent to the Docker daemon and can be inadvertently COPY-ed into ' +
      'the image.',
    badExample: '# no .dockerignore present; COPY . . includes .env, .git, and local credential files',
    goodExample:
      '# .dockerignore\n' +
      '.git\n' +
      '.env\n' +
      'node_modules\n' +
      '*.pem\n' +
      '*.key\n' +
      '.aws/',
    reason: 'Excluding secrets and version-control metadata from the build context prevents them from ever being eligible for inclusion in an image layer.',
  },
  {
    practice: 'Use exec form (JSON array) for CMD/ENTRYPOINT instead of shell form',
    description:
      'Shell form (CMD npm start) runs the command via /bin/sh -c, which does not forward signals ' +
      'correctly to the actual application process and leaves an extra shell process running as PID 1.',
    badExample: 'CMD npm start',
    goodExample: 'CMD ["node", "server.js"]',
    reason: 'Exec form runs the process directly as PID 1, ensuring SIGTERM from "docker stop" / Kubernetes pod termination is delivered correctly for graceful shutdown, and avoids an unnecessary shell process.',
  },
  {
    practice: 'Use an init process to reap zombie processes',
    description:
      'A containerized process running as PID 1 that spawns child processes (and does not itself ' +
      'implement signal forwarding and zombie reaping) can leave defunct processes accumulating.',
    badExample: 'CMD ["node", "server.js"]',
    goodExample: 'ENTRYPOINT ["/usr/bin/tini", "--"]\nCMD ["node", "server.js"]',
    reason: 'tini (or Docker\'s built-in --init flag) correctly reaps zombie child processes and forwards signals, a common gap that leads to resource leaks in long-running containers.',
  },
  {
    practice: 'Verify checksums/signatures of externally fetched artifacts',
    description:
      'Downloading a binary or archive from the internet during the build without verifying its ' +
      'integrity trusts the network path and the remote host completely.',
    badExample: 'RUN curl -sL https://example.com/tool.tar.gz | tar -xz -C /usr/local/bin',
    goodExample:
      'RUN curl -sLO https://example.com/tool.tar.gz \\\n' +
      '    && echo "3f8a1c9e6d2b...  tool.tar.gz" | sha256sum -c - \\\n' +
      '    && tar -xzf tool.tar.gz -C /usr/local/bin',
    reason: 'Verifying a published checksum (or GPG signature) before extracting/executing a downloaded artifact prevents silent substitution via a compromised mirror or MITM.',
  },
  {
    practice: 'Avoid using the root filesystem as a single monolithic layer; use LABEL and metadata for traceability',
    description:
      'Images without build metadata (source commit, build date, maintainer) make incident ' +
      'response and vulnerability-to-deployment mapping far harder.',
    badExample: 'FROM alpine\nCOPY app /app\nCMD ["/app"]',
    goodExample:
      'FROM alpine\n' +
      'LABEL org.opencontainers.image.source="https://github.com/org/repo" \\\n' +
      '      org.opencontainers.image.revision="$GIT_SHA" \\\n' +
      '      org.opencontainers.image.created="$BUILD_DATE"\n' +
      'COPY app /app\n' +
      'CMD ["/app"]',
    reason: 'Standard OCI labels let security tooling and incident responders trace a running image back to the exact source commit and build pipeline that produced it.',
  },
  {
    practice: 'Scan images for vulnerabilities as part of the build pipeline, not just periodically',
    description:
      'Relying only on scheduled, out-of-band scans lets a newly built image with known-fixable ' +
      'CVEs reach production before anyone reviews the results.',
    badExample: '# CI pipeline: docker build -> docker push, with no scan step',
    goodExample:
      '# CI pipeline step after build:\n' +
      'trivy image --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed myapp:$CI_COMMIT_SHA',
    reason: 'Gating the pipeline on scan results (failing the build on fixable HIGH/CRITICAL CVEs) prevents known-vulnerable images from ever reaching a registry that feeds production.',
  },
  {
    practice: 'Avoid storing application state or persistent data inside the container filesystem',
    description:
      'Writing databases, uploaded files, or other persistent state directly into the container\'s ' +
      'writable layer ties data lifecycle to container lifecycle and often forces the filesystem ' +
      'to remain writable and world-accessible.',
    badExample: '# Application writes uploaded files to /app/uploads inside the container with no external volume',
    goodExample:
      'VOLUME ["/app/uploads"]\n' +
      '# docker run -v uploads-data:/app/uploads myapp:1.0',
    reason: 'Externalizing persistent state to a named volume (or object storage) allows the root filesystem to remain read-only and keeps data intact across container replacement.',
  },
  {
    practice: 'Set explicit resource limits at the orchestration layer, not just documentation',
    description:
      'Relying on comments or README notes about "recommended" memory/CPU limits instead of ' +
      'enforcing them in the deployment manifest means the limits are frequently forgotten in ' +
      'practice.',
    badExample: '# README: "recommend running with --memory=512m"',
    goodExample:
      'resources:\n' +
      '  limits:\n' +
      '    memory: "512Mi"\n' +
      '    cpu: "500m"\n' +
      '  requests:\n' +
      '    memory: "256Mi"\n' +
      '    cpu: "250m"',
    reason: 'Enforcing limits/requests directly in the Kubernetes manifest (or docker run flags) guarantees the constraint is actually applied every time the workload is deployed, preventing resource-exhaustion denial of service.',
  },
];

// =============================================================================
// 6. K8S_NETWORK_POLICIES
// =============================================================================

const K8S_NETWORK_POLICIES = [

  {
    name: 'Default deny all ingress',
    description:
      'Baseline policy that blocks all inbound traffic to every pod in the namespace unless a ' +
      'more specific NetworkPolicy explicitly allows it. This should be the first policy applied ' +
      'to any namespace before layering on targeted allow rules.',
    yaml:
      'apiVersion: networking.k8s.io/v1\n' +
      'kind: NetworkPolicy\n' +
      'metadata:\n' +
      '  name: default-deny-ingress\n' +
      '  namespace: production\n' +
      'spec:\n' +
      '  podSelector: {}\n' +
      '  policyTypes:\n' +
      '    - Ingress\n',
    useCase: 'Applied to every application namespace as the security baseline before adding narrower allow policies.',
  },

  {
    name: 'Default deny all egress',
    description:
      'Blocks all outbound traffic from every pod in the namespace by default, preventing a ' +
      'compromised pod from freely reaching internal services, the internet, or the cloud ' +
      'metadata API unless explicitly permitted.',
    yaml:
      'apiVersion: networking.k8s.io/v1\n' +
      'kind: NetworkPolicy\n' +
      'metadata:\n' +
      '  name: default-deny-egress\n' +
      '  namespace: production\n' +
      'spec:\n' +
      '  podSelector: {}\n' +
      '  policyTypes:\n' +
      '    - Egress\n',
    useCase: 'Combined with default-deny-ingress to fully isolate a namespace by default; particularly important for preventing data exfiltration from a compromised workload.',
  },

  {
    name: 'Allow DNS egress (required alongside default-deny-egress)',
    description:
      'When a default-deny-egress policy is in place, pods lose the ability to resolve DNS unless ' +
      'traffic to the cluster DNS service (CoreDNS/kube-dns) is explicitly permitted on UDP/TCP 53.',
    yaml:
      'apiVersion: networking.k8s.io/v1\n' +
      'kind: NetworkPolicy\n' +
      'metadata:\n' +
      '  name: allow-dns-egress\n' +
      '  namespace: production\n' +
      'spec:\n' +
      '  podSelector: {}\n' +
      '  policyTypes:\n' +
      '    - Egress\n' +
      '  egress:\n' +
      '    - to:\n' +
      '        - namespaceSelector: {}\n' +
      '      ports:\n' +
      '        - protocol: UDP\n' +
      '          port: 53\n' +
      '        - protocol: TCP\n' +
      '          port: 53\n',
    useCase: 'Must be applied together with any default-deny-egress policy so application pods can still resolve internal and external DNS names.',
  },

  {
    name: 'Allow ingress from a specific namespace',
    description:
      'Permits inbound traffic to pods only from workloads running in a specifically labeled ' +
      'namespace, commonly used to allow an "ingress-nginx" or API gateway namespace to reach ' +
      'backend application pods while blocking every other namespace.',
    yaml:
      'apiVersion: networking.k8s.io/v1\n' +
      'kind: NetworkPolicy\n' +
      'metadata:\n' +
      '  name: allow-from-ingress-namespace\n' +
      '  namespace: production\n' +
      'spec:\n' +
      '  podSelector:\n' +
      '    matchLabels:\n' +
      '      app: web-frontend\n' +
      '  policyTypes:\n' +
      '    - Ingress\n' +
      '  ingress:\n' +
      '    - from:\n' +
      '        - namespaceSelector:\n' +
      '            matchLabels:\n' +
      '              kubernetes.io/metadata.name: ingress-nginx\n' +
      '      ports:\n' +
      '        - protocol: TCP\n' +
      '          port: 8080\n',
    useCase: 'Restricts which namespace can route external traffic into a given application, preventing arbitrary in-cluster pods from bypassing the ingress controller.',
  },

  {
    name: 'Allow ingress from specific pods (by label) within the same namespace',
    description:
      'Restricts a backend service (e.g. an internal API) so that only pods carrying a specific ' +
      'label — typically the legitimate frontend/service tier — can connect to it, blocking every ' +
      'other pod in the namespace.',
    yaml:
      'apiVersion: networking.k8s.io/v1\n' +
      'kind: NetworkPolicy\n' +
      'metadata:\n' +
      '  name: allow-frontend-to-api\n' +
      '  namespace: production\n' +
      'spec:\n' +
      '  podSelector:\n' +
      '    matchLabels:\n' +
      '      app: internal-api\n' +
      '  policyTypes:\n' +
      '    - Ingress\n' +
      '  ingress:\n' +
      '    - from:\n' +
      '        - podSelector:\n' +
      '            matchLabels:\n' +
      '              app: web-frontend\n' +
      '      ports:\n' +
      '        - protocol: TCP\n' +
      '          port: 8443\n',
    useCase: 'Enforces east-west microsegmentation so a compromised unrelated pod in the same namespace cannot directly call an internal API service.',
  },

  {
    name: 'Isolate database pods (allow only application tier, deny all else)',
    description:
      'Locks down a database StatefulSet so that only pods explicitly labeled as the ' +
      'application\'s backend tier can connect on the database port, and no other ingress or ' +
      'egress is permitted from the database pods themselves.',
    yaml:
      'apiVersion: networking.k8s.io/v1\n' +
      'kind: NetworkPolicy\n' +
      'metadata:\n' +
      '  name: isolate-postgres\n' +
      '  namespace: production\n' +
      'spec:\n' +
      '  podSelector:\n' +
      '    matchLabels:\n' +
      '      app: postgres\n' +
      '  policyTypes:\n' +
      '    - Ingress\n' +
      '    - Egress\n' +
      '  ingress:\n' +
      '    - from:\n' +
      '        - podSelector:\n' +
      '            matchLabels:\n' +
      '              tier: backend\n' +
      '      ports:\n' +
      '        - protocol: TCP\n' +
      '          port: 5432\n' +
      '  egress:\n' +
      '    - to:\n' +
      '        - namespaceSelector: {}\n' +
      '      ports:\n' +
      '        - protocol: UDP\n' +
      '          port: 53\n',
    useCase: 'Ensures the database can be reached only by the intended backend tier and can only make outbound DNS calls, dramatically limiting lateral movement and exfiltration if the database pod itself is ever compromised.',
  },

  {
    name: 'Allow egress only to specific external CIDR (e.g. a third-party payment API)',
    description:
      'Restricts a pod\'s outbound traffic to a named, narrow set of external IP ranges, blocking ' +
      'all other internet destinations, which limits data exfiltration paths and callback ' +
      'channels for malware.',
    yaml:
      'apiVersion: networking.k8s.io/v1\n' +
      'kind: NetworkPolicy\n' +
      'metadata:\n' +
      '  name: allow-egress-payment-provider\n' +
      '  namespace: production\n' +
      'spec:\n' +
      '  podSelector:\n' +
      '    matchLabels:\n' +
      '      app: checkout-service\n' +
      '  policyTypes:\n' +
      '    - Egress\n' +
      '  egress:\n' +
      '    - to:\n' +
      '        - ipBlock:\n' +
      '            cidr: 203.0.113.0/24\n' +
      '      ports:\n' +
      '        - protocol: TCP\n' +
      '          port: 443\n',
    useCase: 'Applied to a payment or third-party integration service so it can only reach the known IP range of that provider\'s API, blocking any other outbound destination even if the pod is compromised.',
  },

  {
    name: 'Deny egress to the cloud metadata API',
    description:
      'Explicitly blocks pods from reaching the cloud instance metadata endpoint ' +
      '(169.254.169.254), closing off the SSRF-to-credential-theft path described in the ' +
      'K8S_ATTACK_TECHNIQUES entry for metadata API abuse. Written as a "deny" using an ipBlock ' +
      'except clause combined with a default-deny-egress baseline.',
    yaml:
      'apiVersion: networking.k8s.io/v1\n' +
      'kind: NetworkPolicy\n' +
      'metadata:\n' +
      '  name: block-metadata-api\n' +
      '  namespace: production\n' +
      'spec:\n' +
      '  podSelector: {}\n' +
      '  policyTypes:\n' +
      '    - Egress\n' +
      '  egress:\n' +
      '    - to:\n' +
      '        - ipBlock:\n' +
      '            cidr: 0.0.0.0/0\n' +
      '            except:\n' +
      '              - 169.254.169.254/32\n',
    useCase: 'Deployed cluster-wide (or per sensitive namespace) to prevent any application, including one compromised via SSRF, from ever reaching the instance metadata service directly.',
  },

  {
    name: 'Allow specific ports only (multi-port service)',
    description:
      'Permits ingress traffic only on the exact ports a multi-port service actually listens on ' +
      '(e.g. a metrics port and an application port), blocking any other port that might be ' +
      'inadvertently opened by a debugging tool or misconfiguration.',
    yaml:
      'apiVersion: networking.k8s.io/v1\n' +
      'kind: NetworkPolicy\n' +
      'metadata:\n' +
      '  name: allow-app-and-metrics-ports\n' +
      '  namespace: production\n' +
      'spec:\n' +
      '  podSelector:\n' +
      '    matchLabels:\n' +
      '      app: orders-service\n' +
      '  policyTypes:\n' +
      '    - Ingress\n' +
      '  ingress:\n' +
      '    - from:\n' +
      '        - podSelector:\n' +
      '            matchLabels:\n' +
      '              tier: frontend\n' +
      '      ports:\n' +
      '        - protocol: TCP\n' +
      '          port: 8080\n' +
      '    - from:\n' +
      '        - namespaceSelector:\n' +
      '            matchLabels:\n' +
      '              kubernetes.io/metadata.name: monitoring\n' +
      '      ports:\n' +
      '        - protocol: TCP\n' +
      '          port: 9090\n',
    useCase: 'Used for services that expose both an application port (reachable from the frontend tier) and a Prometheus metrics port (reachable only from the monitoring namespace).',
  },

  {
    name: 'Allow traffic only within the same namespace',
    description:
      'Restricts every pod in a namespace to only communicate with other pods in that same ' +
      'namespace, providing simple, coarse-grained tenant isolation for multi-tenant clusters ' +
      'where each team/customer has a dedicated namespace.',
    yaml:
      'apiVersion: networking.k8s.io/v1\n' +
      'kind: NetworkPolicy\n' +
      'metadata:\n' +
      '  name: allow-same-namespace-only\n' +
      '  namespace: tenant-a\n' +
      'spec:\n' +
      '  podSelector: {}\n' +
      '  policyTypes:\n' +
      '    - Ingress\n' +
      '  ingress:\n' +
      '    - from:\n' +
      '        - podSelector: {}\n',
    useCase: 'Deployed identically (with the namespace field changed) in every tenant namespace of a multi-tenant cluster to guarantee cross-tenant pods can never reach each other directly.',
  },

  {
    name: 'Allow ingress from an authorized monitoring/observability namespace only',
    description:
      'Permits Prometheus, or another centralized monitoring system running in a dedicated ' +
      'namespace, to scrape metrics endpoints across application namespaces, while blocking all ' +
      'other cross-namespace ingress.',
    yaml:
      'apiVersion: networking.k8s.io/v1\n' +
      'kind: NetworkPolicy\n' +
      'metadata:\n' +
      '  name: allow-prometheus-scrape\n' +
      '  namespace: production\n' +
      'spec:\n' +
      '  podSelector: {}\n' +
      '  policyTypes:\n' +
      '    - Ingress\n' +
      '  ingress:\n' +
      '    - from:\n' +
      '        - namespaceSelector:\n' +
      '            matchLabels:\n' +
      '              kubernetes.io/metadata.name: monitoring\n' +
      '          podSelector:\n' +
      '            matchLabels:\n' +
      '              app.kubernetes.io/name: prometheus\n' +
      '      ports:\n' +
      '        - protocol: TCP\n' +
      '          port: 9100\n',
    useCase: 'Ensures only the specific, identified Prometheus pod in the monitoring namespace (not just any pod in that namespace) can reach the metrics port of every application in production.',
  },

  {
    name: 'Egress allow-list for a CI/CD runner pod',
    description:
      'Constrains a CI/CD build agent pod so it can only reach the internal container registry, ' +
      'the source control system, and DNS, preventing a compromised build (e.g. via a malicious ' +
      'dependency executed during "npm install") from reaching arbitrary internal or external ' +
      'hosts.',
    yaml:
      'apiVersion: networking.k8s.io/v1\n' +
      'kind: NetworkPolicy\n' +
      'metadata:\n' +
      '  name: ci-runner-egress-allowlist\n' +
      '  namespace: ci\n' +
      'spec:\n' +
      '  podSelector:\n' +
      '    matchLabels:\n' +
      '      app: ci-runner\n' +
      '  policyTypes:\n' +
      '    - Egress\n' +
      '  egress:\n' +
      '    - to:\n' +
      '        - namespaceSelector:\n' +
      '            matchLabels:\n' +
      '              kubernetes.io/metadata.name: registry\n' +
      '      ports:\n' +
      '        - protocol: TCP\n' +
      '          port: 443\n' +
      '    - to:\n' +
      '        - namespaceSelector: {}\n' +
      '      ports:\n' +
      '        - protocol: UDP\n' +
      '          port: 53\n' +
      '        - protocol: TCP\n' +
      '          port: 53\n',
    useCase: 'Reduces the blast radius of a supply-chain compromise during the build process by preventing the CI runner from reaching arbitrary internal services or exfiltrating data externally.',
  },
];
