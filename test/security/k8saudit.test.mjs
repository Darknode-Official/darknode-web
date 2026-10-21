// Kubernetes Audit engine tests (public/js/appsec/k8saudit-engine.js).
// Parser fixtures in the exact kubectl / kube-bench / can-i layouts, Secret value
// stripping, RBAC resolution (aggregated ClusterRoles, group subjects), every
// detection on a crafted positive and a silent negative, exposure chains,
// skipped-check reporting, determinism, exports and selfTest.

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, VERSION, DEFAULTS, COLUMNS, DETECTIONS, KINDS,
  parseInput, parseFile, parseCanI, analyze, describeFiles, findingsToCsv, workloadsToCsv, rbacMatrixCsv, remediationYaml, summaryText,
  exampleDataset, selfTest, parseImage, parseVersion, selectorMatches, resolveRoles, rbacGraph, resolveWorkloads, dangerousPerms, literalSecretEnv, toYaml, normalizeObject,
} from "../../public/js/appsec/k8saudit-engine.js";

// ---------------------------------------------------------------------------
// Builders and fixtures
// ---------------------------------------------------------------------------
const J = (v) => JSON.stringify(v, null, 2);
const list = (items) => J({ apiVersion: "v1", kind: "List", items, metadata: { resourceVersion: "" } });
const ns = (name, labels = {}) => ({ apiVersion: "v1", kind: "Namespace", metadata: { name, labels: { "kubernetes.io/metadata.name": name, ...labels } }, status: { phase: "Active" } });
const dep = (name, namespace, spec, labels = { app: name }, extra = {}) => ({ apiVersion: "apps/v1", kind: "Deployment", metadata: { name, namespace, uid: "uid-" + namespace + "-" + name, labels }, spec: { replicas: 1, selector: { matchLabels: labels }, template: { metadata: { labels }, spec } }, ...extra });
const good = (image = "registry.test.darknode.ai/app/api:1.2.3") => ({
  automountServiceAccountToken: false, securityContext: { runAsNonRoot: true, runAsUser: 10001, seccompProfile: { type: "RuntimeDefault" } },
  containers: [{ name: "c", image, resources: { limits: { cpu: "1", memory: "1Gi" } }, readinessProbe: { tcpSocket: { port: 8080 } }, securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } } }],
});
const withC = (spec, c) => ({ ...spec, containers: [{ ...spec.containers[0], ...c, securityContext: { ...spec.containers[0].securityContext, ...(c.securityContext || {}) } }] });
const svc = (name, namespace, type, selector) => ({ apiVersion: "v1", kind: "Service", metadata: { name, namespace }, spec: { type, selector, ports: [{ port: 80, protocol: "TCP", ...(type === "NodePort" || type === "LoadBalancer" ? { nodePort: 30080 } : {}) }] } });
const crb = (name, role, subjects) => ({ apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", metadata: { name }, roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "ClusterRole", name: role }, subjects });
const rb = (name, namespace, kind, role, subjects) => ({ apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding", metadata: { name, namespace }, roleRef: { apiGroup: "rbac.authorization.k8s.io", kind, name: role }, subjects });
const cr = (name, rules, labels, aggregationRule) => ({ apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRole", metadata: { name, ...(labels ? { labels } : {}) }, rules, ...(aggregationRule ? { aggregationRule } : {}) });
const role = (name, namespace, rules) => ({ apiVersion: "rbac.authorization.k8s.io/v1", kind: "Role", metadata: { name, namespace }, rules });
const sa = (name, namespace, extra = {}) => ({ apiVersion: "v1", kind: "ServiceAccount", metadata: { name, namespace }, ...extra });
const np = (name, namespace, podSelector, policyTypes, extra = {}) => ({ apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name, namespace }, spec: { podSelector, policyTypes, ...extra } });
const U = (name) => ({ apiGroup: "rbac.authorization.k8s.io", kind: "User", name });
const G = (name) => ({ apiGroup: "rbac.authorization.k8s.io", kind: "Group", name });
const S = (name, namespace) => ({ kind: "ServiceAccount", name, namespace });
const run = (items, opts = {}) => analyze(parseInput([{ name: "dump.json", text: list(items) }]), { now: "2026-10-01", ...opts });
const by = (r, check) => r.findings.filter((f) => f.check === check);

// Verbatim `kubectl get deploy,secret -n payments -o yaml` layout (List with managedFields + last-applied).
const YAML_DUMP = `apiVersion: v1
items:
- apiVersion: apps/v1
  kind: Deployment
  metadata:
    annotations:
      deployment.kubernetes.io/revision: "3"
      kubectl.kubernetes.io/last-applied-configuration: |
        {"apiVersion":"apps/v1","kind":"Deployment","metadata":{"annotations":{},"name":"api","namespace":"payments"}}
    creationTimestamp: "2026-01-02T03:04:05Z"
    generation: 3
    labels:
      app: api
    managedFields:
    - apiVersion: apps/v1
      fieldsType: FieldsV1
      fieldsV1:
        f:spec:
          f:template:
            f:spec:
              f:containers:
                k:{"name":"api"}:
                  .: {}
                  f:image: {}
      manager: kubectl-client-side-apply
      operation: Update
      time: "2026-01-02T03:04:05Z"
    name: api
    namespace: payments
    resourceVersion: "12345"
    uid: 0a1b2c3d-1111-2222-3333-444455556666
  spec:
    progressDeadlineSeconds: 600
    replicas: 3
    selector:
      matchLabels:
        app: api
    template:
      metadata:
        creationTimestamp: null
        labels:
          app: api
      spec:
        containers:
        - env:
          - name: DB_PASSWORD
            value: hunter2hunter2
          image: ghcr.io/acme/api:1.4.2
          imagePullPolicy: IfNotPresent
          name: api
          securityContext:
            privileged: true
        dnsPolicy: ClusterFirst
        restartPolicy: Always
  status:
    availableReplicas: 3
- apiVersion: v1
  data:
    password: aHVudGVyMmh1bnRlcjI=
    username: YXBp
  kind: Secret
  metadata:
    creationTimestamp: "2026-01-02T03:04:05Z"
    name: db
    namespace: payments
    resourceVersion: "999"
    uid: 9a9b9c9d-1111-2222-3333-444455556666
  type: Opaque
kind: List
metadata:
  resourceVersion: ""
`;
// Multi-document manifest-style YAML (as `kubectl get -o yaml` per object, joined by ---).
const MULTI_DOC = `apiVersion: v1
kind: Namespace
metadata:
  name: staging
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app
  namespace: staging
data:
  api_key: abc123secretvalue
  log_level: debug
`;
// kube-bench `--json` output, wrapped form ([{Controls:[...]}]) as emitted by newer releases.
const KUBE_BENCH = J([{ Controls: [
  { id: "1", version: "cis-1.9", detected_version: "1.29", text: "Control Plane Security Configuration", node_type: "master", tests: [{ section: "1.2", type: "", pass: 0, fail: 1, warn: 0, info: 0, desc: "API Server", results: [
    { test_number: "1.2.1", test_desc: "Ensure that the --anonymous-auth argument is set to false (Manual)", audit: "/bin/ps -ef | grep kube-apiserver | grep -v grep", AuditEnv: "", AuditConfig: "", type: "", remediation: "Set --anonymous-auth=false", test_info: ["Set --anonymous-auth=false"], status: "FAIL", actual_value: "", scored: false, IsMultiple: false, expected_result: "", reason: "" }] }], total_pass: 0, total_fail: 1, total_warn: 0, total_info: 0 },
  { id: "4", version: "cis-1.9", detected_version: "1.29", text: "Worker Node Security Configuration", node_type: "node", tests: [{ section: "4.2", type: "", pass: 1, fail: 1, warn: 1, info: 0, desc: "Kubelet", results: [
    { test_number: "4.2.1", test_desc: "Ensure that the --anonymous-auth argument is set to false (Automated)", audit: "/bin/ps -fC kubelet", remediation: "Disable anonymous auth", status: "FAIL", actual_value: "true", scored: true, expected_result: "'authentication.anonymous.enabled' is equal to 'false'" },
    { test_number: "4.2.2", test_desc: "Ensure that the --authorization-mode argument is not set to AlwaysAllow (Automated)", remediation: "", status: "PASS", scored: true },
    { test_number: "4.2.9", test_desc: "Ensure that the eventRecordQPS argument is set (Manual)", remediation: "Set eventRecordQPS", status: "WARN", scored: false }] }] },
  { id: "5", version: "cis-1.9", text: "Kubernetes Policies", node_type: "policies", tests: [{ section: "5.1", desc: "RBAC and Service Accounts", results: [
    { test_number: "5.1.1", test_desc: "Ensure that the cluster-admin role is only used where required (Manual)", remediation: "Identify all clusterrolebindings to the cluster-admin role.", status: "FAIL", scored: false }] }] },
] }]);
// `kubectl auth can-i --list` (column layout as printed by kubectl).
const CAN_I = [
  "Resources                                       Non-Resource URLs   Resource Names   Verbs",
  "selfsubjectaccessreviews.authorization.k8s.io   []                  []               [create]",
  "selfsubjectrulesreviews.authorization.k8s.io    []                  []               [create]",
  "pods/exec                                       []                  []               [create get]",
  "secrets                                         []                  [db-creds]       [get]",
  "deployments.apps                                []                  []               [get list]",
  "                                                [/api/*]            []               [get]",
  "                                                [/healthz]          []               [get]",
].join("\n");
const VERSION_JSON = J({ major: "1", minor: "29", gitVersion: "v1.29.6", gitCommit: "a".repeat(40), gitTreeState: "clean", buildDate: "2024-06-11T20:21:00Z", goVersion: "go1.21.11", compiler: "gc", platform: "linux/amd64" });
const EOL = { product: "kubernetes", cycles: [{ cycle: "1.30", eol: "2025-07-15", latest: "1.30.14" }, { cycle: "1.29", eol: "2025-02-28", latest: "1.29.15" }, { cycle: "1.28", eol: "2024-10-28", latest: "1.28.15" }] };

// ---------------------------------------------------------------------------
group("k8saudit: parsers", () => {
  test("exports keep their contract names", () => {
    assert.equal(TOOL_ID, "k8saudit"); assert.ok(VERSION); assert.ok(DEFAULTS.authenticatedCritical === true); assert.ok(COLUMNS.kind); assert.ok(KINDS.includes("ClusterRoleBinding"));
    assert.ok(DETECTIONS.every((d) => d.controls.length >= 1));
  });
  test("kubectl List JSON is flattened, sorted and de-duplicated by uid across files", () => {
    const a = dep("b", "ns1", good()), b = dep("a", "ns1", good());
    const ds = parseInput([{ name: "one.json", text: list([a, b]) }, { name: "two.json", text: list([a]) }]);
    assert.equal(ds.objects.length, 2); assert.equal(ds.stats.duplicates, 1);
    assert.deepEqual(ds.objects.map((o) => o.metadata.name), ["a", "b"]);
    assert.equal(ds.files[0].kind, "k8s"); assert.equal(ds.files[0].kinds.Deployment, 2);
  });
  test("kubectl -o yaml List parses; managedFields and last-applied are dropped", () => {
    const ds = parseInput([{ name: "payments.yaml", text: YAML_DUMP }]);
    assert.equal(ds.objects.length, 2);
    const d = ds.objects.find((o) => o.kind === "Deployment");
    assert.equal(d.metadata.managedFields, undefined);
    assert.equal(d.metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"], undefined);
    assert.equal(d.spec.template.spec.containers[0].securityContext.privileged, true);
  });
  test("Secret data values are stripped at parse time; key names kept", () => {
    const ds = parseInput([{ name: "payments.yaml", text: YAML_DUMP }]);
    const s = ds.objects.find((o) => o.kind === "Secret");
    assert.equal(s.data, undefined); assert.deepEqual(s.dataKeys, ["password", "username"]);
    assert.ok(!JSON.stringify(ds).includes("aHVudGVyMmh1bnRlcjI="));
    assert.ok(!JSON.stringify(analyze(ds)).includes("aHVudGVyMmh1bnRlcjI="));
  });
  test("stringData and ConfigMap values are stripped too", () => {
    const n = normalizeObject({ apiVersion: "v1", kind: "Secret", metadata: { name: "x", namespace: "a" }, stringData: { token: "plain-text-token" } });
    assert.ok(!JSON.stringify(n).includes("plain-text-token")); assert.deepEqual(n.dataKeys, ["token"]);
    const ds = parseInput([{ name: "multi.yaml", text: MULTI_DOC }]);
    assert.ok(!JSON.stringify(ds).includes("abc123secretvalue"));
    assert.deepEqual(ds.objects.find((o) => o.kind === "ConfigMap").dataKeys, ["api_key", "log_level"]);
  });
  test("multi-document YAML yields one object per document", () => {
    const ds = parseInput([{ name: "multi.yaml", text: MULTI_DOC }]);
    assert.deepEqual(ds.objects.map((o) => o.kind).sort(), ["ConfigMap", "Namespace"]);
  });
  test("kube-bench JSON (wrapped array form) is recognised", () => {
    const f = parseFile(KUBE_BENCH, "kube-bench.json");
    assert.equal(f.file.kind, "kube-bench"); assert.equal(f.kubeBench.Controls.length, 3);
  });
  test("kubectl auth can-i --list text is parsed into rules", () => {
    const c = parseCanI(CAN_I, "can-i-test@darknode.ai.txt");
    assert.equal(c.subject, "test@darknode.ai");
    const exec = c.rows.find((r) => r.resource === "pods/exec");
    assert.deepEqual(exec.verbs, ["create", "get"]);
    assert.deepEqual(c.rows.find((r) => r.resource === "secrets").resourceNames, ["db-creds"]);
    assert.equal(parseFile(CAN_I, "x.txt").file.kind, "can-i");
  });
  test("/version JSON is recognised", () => {
    const f = parseFile(VERSION_JSON, "version.json");
    assert.equal(f.file.kind, "version"); assert.equal(f.version.gitVersion, "v1.29.6");
  });
  test("unrecognised files are skipped with a reason, never guessed", () => {
    const ds = parseInput([{ name: "notes.txt", text: "hello world\nnot a dump" }, { name: "empty.json", text: "" }]);
    assert.equal(ds.objects.length, 0); assert.equal(ds.skipped.length, 2);
    assert.ok(ds.skipped.every((s) => s.check === "parse" && s.reason));
  });
  test("describeFiles returns per-file kinds without objects", () => {
    const d = describeFiles([{ name: "a.json", text: list([ns("a"), dep("x", "a", good())]) }, { name: "kb.json", text: KUBE_BENCH }]);
    assert.equal(d.files[0].kind, "k8s"); assert.equal(d.files[1].kind, "kube-bench"); assert.equal(d.objects, undefined); assert.equal(d.stats.kinds.Deployment, 1);
  });
  test("image and version helpers", () => {
    assert.deepEqual([parseImage("nginx").registry, parseImage("nginx").repository, parseImage("nginx").floating], ["docker.io", "library/nginx", true]);
    const p = parseImage("registry.test.darknode.ai:5000/team/app:1.2@sha256:abc");
    assert.equal(p.registry, "registry.test.darknode.ai:5000"); assert.equal(p.tag, "1.2"); assert.equal(p.pinned, true);
    assert.equal(parseVersion("v1.28.3-eks-1234").minor, 28);
  });
  test("toYaml re-serialises deterministically with sorted keys", () => {
    assert.equal(toYaml({ b: 1, a: { c: [true, "x y"] } }), "a:\n  c:\n    - true\n    - x y\nb: 1");
  });
});

group("k8saudit: RBAC", () => {
  test("aggregated ClusterRole inherits rules by label selector (and transitively)", () => {
    const objs = [
      cr("top", [], null, { clusterRoleSelectors: [{ matchLabels: { agg: "top" } }] }),
      cr("mid", [], { agg: "top" }, { clusterRoleSelectors: [{ matchExpressions: [{ key: "agg", operator: "In", values: ["mid"] }] }] }),
      cr("leaf", [{ apiGroups: [""], resources: ["secrets"], verbs: ["list"] }], { agg: "mid" }),
    ].map(normalizeObject);
    const roles = resolveRoles(objs);
    assert.deepEqual(dangerousPerms(roles.get("ClusterRole/top").rules).map((p) => p.key), ["secrets"]);
    assert.deepEqual(roles.get("ClusterRole/top").aggregatedFrom, ["mid"]);
  });
  test("effective-permission table walks bindings to roles incl. group subjects", () => {
    const r = run([role("exec", "app", [{ apiGroups: [""], resources: ["pods/exec"], verbs: ["create"] }]), rb("devs-exec", "app", "Role", "exec", [G("devs")]), cr("viewer-secrets", [{ apiGroups: [""], resources: ["secrets"], verbs: ["get"] }]), crb("auditors", "viewer-secrets", [G("auditors"), U("test@darknode.ai")])]);
    const devs = r.tables.subjects.find((s) => s.name === "devs");
    assert.equal(devs.kind, "Group"); assert.ok(devs.dangerous.includes("pods/exec (ns app)"));
    const u = r.tables.subjects.find((s) => s.name === "test@darknode.ai");
    assert.ok(u.dangerous.includes("read secrets")); assert.equal(u.scope, "cluster");
  });
  test("cluster-admin to system:authenticated is critical; toggle off makes it high", () => {
    const items = [crb("everyone", "cluster-admin", [G("system:authenticated")])];
    assert.equal(by(run(items), "rbac.cluster_admin")[0].severity, "critical");
    assert.equal(by(run(items, { authenticatedCritical: false }), "rbac.cluster_admin")[0].severity, "high");
  });
  test("cluster-admin to a user is high with an IDENTITY asset; built-in system:masters is silent", () => {
    const r = run([crb("cluster-admin", "cluster-admin", [G("system:masters")]), crb("ops", "cluster-admin", [U("test@darknode.ai")])]);
    const f = by(r, "rbac.cluster_admin");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "high");
    assert.ok(f[0].assets.some((a) => a.type === "IDENTITY" && a.name === "test@darknode.ai"));
    assert.equal(r.summary.clusterAdminSubjects, 1);
  });
  test("cluster-admin via RoleBinding is namespace-scoped medium", () => {
    const f = by(run([rb("ns-admin", "app", "ClusterRole", "cluster-admin", [U("test@darknode.ai")])]), "rbac.cluster_admin");
    assert.equal(f[0].severity, "medium");
  });
  test("wildcard rules fire for custom roles only", () => {
    const r = run([cr("custom", [{ apiGroups: ["*"], resources: ["*"], verbs: ["*"] }]), crb("c", "custom", [S("bot", "app")]), cr("system:controller:x", [{ apiGroups: ["*"], resources: ["*"], verbs: ["*"] }])]);
    const f = by(r, "rbac.wildcard");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "high");
    const narrow = run([cr("narrow", [{ apiGroups: [""], resources: ["configmaps"], verbs: ["get"] }]), crb("n", "narrow", [S("bot", "app")])]);
    assert.equal(by(narrow, "rbac.wildcard").length, 0);
  });
  test("dangerous roles: impersonate / escalate / bind / nodes/proxy; unbound role is low review", () => {
    const rules = [{ apiGroups: [""], resources: ["users"], verbs: ["impersonate"] }, { apiGroups: ["rbac.authorization.k8s.io"], resources: ["clusterroles"], verbs: ["bind", "escalate"] }, { apiGroups: [""], resources: ["nodes/proxy"], verbs: ["get"] }];
    const bound = by(run([cr("power", rules), crb("p", "power", [S("bot", "app")])]), "rbac.dangerous_role")[0];
    assert.equal(bound.severity, "high");
    for (const k of ["impersonate", "escalate roles", "bind roles", "nodes/proxy"]) assert.ok(bound.title.includes(k), k);
    const unbound = by(run([cr("power", rules)]), "rbac.dangerous_role")[0];
    assert.equal(unbound.severity, "low"); assert.equal(unbound.confidence, "review");
    assert.equal(by(run([cr("ro", [{ apiGroups: [""], resources: ["configmaps"], verbs: ["get"] }])]), "rbac.dangerous_role").length, 0);
  });
  test("dangerous rights to a broad group are critical", () => {
    const f = by(run([cr("sec", [{ apiGroups: [""], resources: ["secrets"], verbs: ["list"] }]), crb("s", "sec", [G("system:authenticated")])]), "rbac.dangerous_role");
    assert.ok(f.some((x) => x.severity === "critical" && x.tags.includes("broad-group")));
  });
  test("orphan bindings: missing role and missing service account", () => {
    const r = run([ns("app"), sa("real", "app"), cr("present", []), crb("a", "ghost-role", [S("real", "app")]), crb("b", "present", [S("ghost", "app")])]);
    const f = by(r, "rbac.orphan_binding")[0];
    assert.equal(f.evidenceCount, 2);
    assert.equal(by(run([ns("app"), sa("real", "app"), cr("present", []), crb("b", "present", [S("real", "app")])]), "rbac.orphan_binding").length, 0);
  });
  test("default service account with roles bound", () => {
    const r = run([role("r", "app", [{ apiGroups: [""], resources: ["pods"], verbs: ["create"] }]), rb("x", "app", "Role", "r", [S("default", "app")])]);
    assert.equal(by(r, "rbac.default_sa_bound").length, 1);
    assert.equal(by(run([rb("x", "app", "ClusterRole", "system:image-puller", [S("default", "app")])]), "rbac.default_sa_bound").length, 0);
  });
  test("default service account automount and unneeded tokens", () => {
    const r = run([sa("default", "app"), sa("api", "app"), dep("w", "app", { ...good(), automountServiceAccountToken: undefined, serviceAccountName: "api" }), crb("noop", "view", [U("someone")])]);
    assert.equal(by(r, "rbac.default_sa_automount").length, 1);
    assert.equal(by(r, "rbac.automount_unneeded")[0].evidence[0].name, "w");
    const neg = run([sa("default", "app", { automountServiceAccountToken: false }), sa("api", "app"), dep("w", "app", good()), crb("noop", "view", [U("someone")])]);
    assert.equal(by(neg, "rbac.default_sa_automount").length + by(neg, "rbac.automount_unneeded").length, 0);
  });
  test("can-i spot check flags pods/exec and named secret read", () => {
    const r = analyze(parseInput([{ name: "can-i-test@darknode.ai.txt", text: CAN_I }]));
    const f = by(r, "cani")[0];
    assert.ok(f.title.includes("pods/exec")); assert.ok(f.description.includes("read secrets (named resources)"));
    assert.equal(f.evidenceCount, 2);
    assert.ok(r.tables.subjects.some((s) => s.source === "can-i" && s.name === "test@darknode.ai"));
  });
});

group("k8saudit: workloads and pod security", () => {
  test("ReplicaSets and Pods collapse into their controller; bare Pods are kept", () => {
    const d = dep("web", "app", good());
    const rs = { apiVersion: "apps/v1", kind: "ReplicaSet", metadata: { name: "web-5d4f8c7b9d", namespace: "app", ownerReferences: [{ kind: "Deployment", name: "web", uid: "uid-app-web" }] }, spec: { replicas: 1, template: { metadata: { labels: { app: "web" } }, spec: good() } } };
    const pod = { apiVersion: "v1", kind: "Pod", metadata: { name: "web-5d4f8c7b9d-abcde", namespace: "app", ownerReferences: [{ kind: "ReplicaSet", name: "web-5d4f8c7b9d" }] }, spec: good(), status: { phase: "Running" } };
    const bare = { apiVersion: "v1", kind: "Pod", metadata: { name: "debug", namespace: "app" }, spec: good(), status: { phase: "Running" } };
    const ws = resolveWorkloads([d, rs, pod, bare].map(normalizeObject));
    assert.deepEqual(ws.map((w) => w.kind + "/" + w.name), ["Deployment/web", "Pod/debug"]);
  });
  test("privileged: high, critical when externally exposed, info for known system DaemonSets", () => {
    const priv = withC(good(), { securityContext: { privileged: true } });
    assert.equal(by(run([dep("p", "app", priv)]), "pod.privileged")[0].severity, "high");
    assert.equal(by(run([dep("p", "app", priv), svc("p", "app", "LoadBalancer", { app: "p" })]), "pod.privileged")[0].severity, "critical");
    const ds = { apiVersion: "apps/v1", kind: "DaemonSet", metadata: { name: "cilium", namespace: "kube-system" }, spec: { template: { metadata: { labels: { k: "cilium" } }, spec: priv } } };
    assert.equal(by(run([ds]), "pod.privileged")[0].severity, "info");
    assert.equal(by(run([dep("ok", "app", good())]), "pod.privileged").length, 0);
  });
  test("host namespaces: hostPID high, hostNetwork alone medium", () => {
    assert.equal(by(run([dep("a", "app", { ...good(), hostPID: true })]), "pod.host_namespaces")[0].severity, "high");
    assert.equal(by(run([dep("a", "app", { ...good(), hostNetwork: true })]), "pod.host_namespaces")[0].severity, "medium");
    assert.equal(by(run([dep("a", "app", good())]), "pod.host_namespaces").length, 0);
  });
  test("hostPath: docker.sock critical, /etc high, other medium", () => {
    const hp = (path) => run([dep("a", "app", { ...good(), volumes: [{ name: "h", hostPath: { path } }] })]);
    assert.equal(by(hp("/var/run/docker.sock"), "pod.hostpath")[0].severity, "critical");
    assert.equal(by(hp("/etc/kubernetes"), "pod.hostpath")[0].severity, "high");
    assert.equal(by(hp("/mnt/cache"), "pod.hostpath")[0].severity, "medium");
  });
  test("privilege escalation, run as root, NET_RAW, seccomp, writable rootfs fire on a bare container", () => {
    const r = run([dep("bare", "app", { containers: [{ name: "c", image: "registry.test.darknode.ai/x:1" }] })]);
    for (const k of ["pod.privilege_escalation", "pod.run_as_root", "pod.net_raw", "pod.no_seccomp", "pod.writable_rootfs", "pod.no_limits", "pod.no_probes"]) assert.equal(by(r, k).length, 1, k);
    const g = run([dep("good", "app", good())]);
    for (const k of ["pod.privilege_escalation", "pod.run_as_root", "pod.net_raw", "pod.no_seccomp", "pod.writable_rootfs", "pod.no_limits", "pod.no_probes"]) assert.equal(by(g, k).length, 0, k);
  });
  test("explicit runAsUser 0 is high, implicit root is medium", () => {
    assert.equal(by(run([dep("a", "app", withC(good(), { securityContext: { runAsUser: 0, runAsNonRoot: false } }))]), "pod.run_as_root")[0].severity, "high");
    assert.equal(by(run([dep("a", "app", { ...good(), securityContext: { seccompProfile: { type: "RuntimeDefault" } } })]), "pod.run_as_root")[0].severity, "medium");
  });
  test("added capabilities: SYS_ADMIN high per workload, NET_BIND_SERVICE ignored", () => {
    const f = by(run([dep("a", "app", withC(good(), { securityContext: { capabilities: { drop: ["ALL"], add: ["SYS_ADMIN"] } } }))]), "pod.added_capabilities");
    assert.equal(f[0].severity, "high");
    assert.equal(by(run([dep("a", "app", withC(good(), { securityContext: { capabilities: { drop: ["ALL"], add: ["NET_BIND_SERVICE"] } } }))]), "pod.added_capabilities").length, 0);
  });
  test("hostPort, shareProcessNamespace, unsafe sysctls, Windows HostProcess", () => {
    const r = run([dep("a", "app", { ...withC(good(), { ports: [{ containerPort: 80, hostPort: 8080 }], securityContext: { windowsOptions: { hostProcess: true } } }), shareProcessNamespace: true, securityContext: { ...good().securityContext, sysctls: [{ name: "kernel.msgmax", value: "65536" }, { name: "net.ipv4.tcp_syncookies", value: "1" }] } })]);
    for (const k of ["pod.hostport", "pod.shared_process_ns", "pod.sysctls", "pod.windows_hostprocess"]) assert.equal(by(r, k).length, 1, k);
    assert.ok(by(r, "pod.sysctls")[0].evidence[0].sysctls.includes("kernel.msgmax") && !by(r, "pod.sysctls")[0].evidence[0].sysctls.includes("tcp_syncookies"));
  });
  test("image tags: latest and untagged flagged, pinned versions silent", () => {
    const r = run([dep("a", "app", good("redis:latest")), dep("b", "app", good("busybox")), dep("c", "app", good("registry.test.darknode.ai/x:1.0"))]);
    assert.equal(by(r, "pod.image_tag")[0].evidenceCount, 2);
    assert.equal(r.tables.images.find((i) => i.image === "redis:latest").tagPolicy, "floating");
  });
  test("registry allow-list: outside list is high; blank list is an info inventory", () => {
    const items = [dep("a", "app", good("docker.io/library/nginx:1.27")), dep("b", "app", good("registry.test.darknode.ai/x:1"))];
    const f = by(run(items, { allowedRegistries: ["registry.test.darknode.ai"] }), "pod.image_registry");
    assert.equal(f[0].severity, "high"); assert.equal(f[0].evidenceCount, 1); assert.equal(f[0].evidence[0].name, "a");
    assert.equal(by(run(items), "pod.image_registry")[0].severity, "info");
  });
  test("literal credential env values are high and masked; secretKeyRef is info", () => {
    const r = run([dep("a", "app", withC(good(), { env: [{ name: "DB_PASSWORD", value: "Sup3rS3cretValue" }, { name: "API_TOKEN", valueFrom: { secretKeyRef: { name: "s", key: "t" } } }, { name: "PASSWORD_FILE", value: "/run/secrets/pw" }] }))]);
    const lit = by(r, "pod.literal_secret_env")[0];
    assert.equal(lit.severity, "high"); assert.ok(!JSON.stringify(r).includes("Sup3rS3cretValue"));
    assert.ok(lit.evidence[0].variables.startsWith("DB_PASSWORD=Su"));
    assert.equal(by(r, "pod.secret_env")[0].severity, "info");
    assert.equal(literalSecretEnv({ env: [{ name: "TOKEN_TTL", value: "3600s-long" }, { name: "LOG_LEVEL", value: "debug" }] }).length, 0);
  });
  test("Pod Security Admission labels: missing medium, privileged high", () => {
    const r = run([ns("a"), ns("b", { "pod-security.kubernetes.io/enforce": "privileged" }), ns("c", { "pod-security.kubernetes.io/enforce": "restricted" }), ns("kube-system")]);
    const f = by(r, "ns.psa_labels");
    assert.equal(f.find((x) => x.severity === "medium").evidence.map((e) => e.namespace).join(), "a");
    assert.equal(f.find((x) => x.severity === "high").evidence[0].namespace, "b");
  });
  test("legacy PodSecurityPolicy objects are reported", () => {
    assert.equal(by(run([{ apiVersion: "policy/v1beta1", kind: "PodSecurityPolicy", metadata: { name: "restricted" }, spec: { privileged: false } }]), "ns.legacy_psp").length, 1);
  });
});

group("k8saudit: network and exposure", () => {
  test("namespace with workloads but no NetworkPolicy; default-deny namespace is clean", () => {
    const r = run([dep("a", "open", good()), dep("b", "closed", good()), np("deny", "closed", {}, ["Ingress", "Egress"])]);
    assert.deepEqual(by(r, "net.no_policy").map((f) => f.id), ["net.no_policy:open"]);
    assert.equal(by(r, "net.no_default_deny").length, 0);
    assert.equal(r.summary.namespacesWithoutNetpol, 1);
  });
  test("policies without a default-deny are reported and uncovered workloads listed", () => {
    const r = run([dep("a", "app", good()), dep("b", "app", good()), np("allow-a", "app", { matchLabels: { app: "a" } }, ["Ingress"], { ingress: [{}] })]);
    assert.ok(by(r, "net.no_default_deny")[0].title.includes("ingress / egress"));
    const unc = by(r, "net.no_policy").find((f) => f.id === "net.no_policy:uncovered");
    assert.equal(unc.evidence[0].name, "b");
  });
  test("NetworkPolicy that selects nothing", () => {
    const r = run([dep("api", "app", good()), np("typo", "app", { matchLabels: { app: "apii" } }, ["Ingress"])]);
    assert.equal(by(r, "net.policy_selects_nothing")[0].evidence[0].policy, "typo");
    assert.equal(by(run([dep("api", "app", good()), np("ok", "app", { matchLabels: { app: "api" } }, ["Ingress"])]), "net.policy_selects_nothing").length, 0);
  });
  test("NetworkPolicy checks are skipped (not guessed) when none are in the dump", () => {
    const r = run([dep("a", "app", good())]);
    assert.equal(by(r, "net.no_policy").length, 0);
    assert.ok(r.skipped.some((s) => s.check === "net.no_policy"));
    assert.equal(by(run([dep("a", "app", good())], { assumeComplete: true }), "net.no_policy").length, 1);
  });
  test("exposure chain: LoadBalancer -> privileged is critical, NodePort -> privileged is high, ClusterIP is silent", () => {
    const priv = withC(good(), { securityContext: { privileged: true } });
    const lb = by(run([dep("p", "app", priv), svc("p", "app", "LoadBalancer", { app: "p" })]), "net.exposed_privileged");
    assert.equal(lb[0].severity, "critical"); assert.ok(lb[0].tags.includes("exposure-chain"));
    assert.equal(by(run([dep("p", "app", priv), svc("p", "app", "NodePort", { app: "p" })]), "net.exposed_privileged")[0].severity, "high");
    assert.equal(by(run([dep("p", "app", priv), svc("p", "app", "ClusterIP", { app: "p" })]), "net.exposed_privileged").length, 0);
  });
  test("exposure chain through an Ingress to a cluster-admin service account", () => {
    const items = [dep("p", "app", { ...good(), serviceAccountName: "api" }), svc("p", "app", "ClusterIP", { app: "p" }), crb("bad", "cluster-admin", [S("api", "app")]),
      { apiVersion: "networking.k8s.io/v1", kind: "Ingress", metadata: { name: "p", namespace: "app" }, spec: { tls: [{ hosts: ["p.test.darknode.ai"] }], rules: [{ host: "p.test.darknode.ai", http: { paths: [{ path: "/", pathType: "Prefix", backend: { service: { name: "p", port: { number: 80 } } } }] } }] } }];
    const r = run(items);
    const f = by(r, "net.exposed_privileged")[0];
    assert.equal(f.severity, "critical"); assert.ok(f.description.includes("service account is cluster-admin"));
    assert.equal(r.tables.workloads[0].exposure, "Ingress");
  });
  test("Ingress without TLS and with ssl-redirect disabled", () => {
    const ing = (name, tls, ann) => ({ apiVersion: "networking.k8s.io/v1", kind: "Ingress", metadata: { name, namespace: "app", annotations: ann }, spec: { ...(tls ? { tls: [{ hosts: ["a.test.darknode.ai"] }] } : {}), rules: [{ host: "a.test.darknode.ai" }] } });
    const r = run([ing("plain", false, {}), ing("noredirect", true, { "nginx.ingress.kubernetes.io/ssl-redirect": "false" }), ing("good", true, {})]);
    assert.deepEqual(by(r, "net.ingress_no_tls").map((f) => f.id), ["net.ingress_no_tls:app/Ingress/plain"]);
    assert.deepEqual(by(r, "net.ingress_ssl_redirect_off").map((f) => f.id), ["net.ingress_ssl_redirect_off:app/Ingress/noredirect"]);
  });
  test("Service whose selector matches no workload", () => {
    const r = run([dep("a", "app", good()), svc("ghost", "app", "ClusterIP", { app: "nothing" }), svc("a", "app", "ClusterIP", { app: "a" })]);
    assert.equal(by(r, "net.service_no_endpoints")[0].evidence.map((e) => e.service).join(), "ghost");
  });
  test("selector matching supports matchExpressions", () => {
    assert.ok(selectorMatches({ matchExpressions: [{ key: "tier", operator: "NotIn", values: ["db"] }, { key: "app", operator: "Exists" }] }, { app: "x", tier: "web" }));
    assert.ok(!selectorMatches({ matchLabels: { app: "x" } }, { app: "y" }));
  });
});

group("k8saudit: secrets, cluster and kube-bench", () => {
  const secret = (name, namespace, type, extra = {}) => ({ apiVersion: "v1", kind: "Secret", metadata: { name, namespace, ...extra }, type, data: { k: "dmFsdWU=" } });
  test("Opaque token-named secret in default is info; elsewhere silent", () => {
    const r = run([secret("api-token", "default", "Opaque"), secret("api-token", "app", "Opaque")]);
    assert.equal(by(r, "secret.opaque_default_ns")[0].evidenceCount, 1);
  });
  test("service account token secrets and dockerconfig spread", () => {
    const r = run([secret("t", "a", "kubernetes.io/service-account-token"), secret("reg", "a", "kubernetes.io/dockerconfigjson"), secret("reg", "b", "kubernetes.io/dockerconfigjson"), secret("reg", "c", "kubernetes.io/dockerconfigjson")]);
    assert.equal(by(r, "secret.sa_token")[0].severity, "medium");
    assert.equal(by(r, "secret.dockerconfig_spread")[0].evidence[0].count, 3);
    assert.equal(by(run([secret("reg", "a", "kubernetes.io/dockerconfigjson"), secret("reg", "b", "kubernetes.io/dockerconfigjson")]), "secret.dockerconfig_spread").length, 0);
  });
  test("shared secret threshold edge", () => {
    const user = (n) => dep(n, "app", { ...good(), volumes: [{ name: "s", secret: { secretName: "shared" } }] });
    const items = [secret("shared", "app", "Opaque"), user("a"), user("b"), user("c")];
    assert.equal(by(run(items), "secret.shared")[0].evidence[0].workloads, 3);
    assert.equal(by(run(items, { sharedSecretWorkloads: 4 }), "secret.shared").length, 0);
  });
  test("ConfigMap credential-like keys judged by name only", () => {
    const r = analyze(parseInput([{ name: "multi.yaml", text: MULTI_DOC }]));
    const f = by(r, "configmap.credential_keys")[0];
    assert.equal(f.evidence[0].keys, "api_key"); assert.equal(f.confidence, "review");
  });
  test("default namespace workloads and unknown kube-system images", () => {
    const r = run([dep("a", "default", good()), dep("mystery", "kube-system", good("docker.io/someone/miner:1.0")), dep("coredns", "kube-system", good("registry.k8s.io/coredns/coredns:v1.11.1"))]);
    assert.equal(by(r, "cluster.default_namespace").length, 1);
    assert.equal(by(r, "cluster.system_unknown_image")[0].evidence.map((e) => e.name).join(), "mystery");
  });
  test("nodes: NotReady info and kubelet skew vs /version", () => {
    const node = (name, kv, ready) => ({ apiVersion: "v1", kind: "Node", metadata: { name }, spec: {}, status: { conditions: [{ type: "Ready", status: ready }], nodeInfo: { kubeletVersion: kv } } });
    const files = [{ name: "nodes.json", text: list([node("a", "v1.29.6", "True"), node("b", "v1.26.1", "False"), node("c", "v1.27.4", "True")]) }, { name: "version.json", text: VERSION_JSON }];
    const r = analyze(parseInput(files), { now: "2026-01-01" });
    assert.equal(by(r, "cluster.node_health")[0].evidence[0].node, "b");
    assert.deepEqual(by(r, "cluster.kubelet_skew")[0].evidence.map((e) => e.node), ["b"]);
    assert.ok(analyze(parseInput(files.slice(0, 1))).skipped.some((s) => s.check === "cluster.kubelet_skew"));
  });
  test("version end-of-life from the passed-in feed; skipped without it", () => {
    const files = [{ name: "version.json", text: VERSION_JSON }];
    const f = by(analyze(parseInput(files), { eol: EOL, now: "2026-10-01" }), "cluster.version_eol")[0];
    assert.equal(f.severity, "high"); assert.ok(f.title.includes("1.29"));
    assert.equal(by(analyze(parseInput(files), { eol: EOL, now: "2025-01-01" }), "cluster.version_eol")[0].severity, "low");
    assert.ok(analyze(parseInput(files), { now: "2026-10-01" }).skipped.some((s) => s.check === "cluster.version_eol"));
    assert.ok(analyze(parseInput(files), { eol: { data: [EOL] }, now: "2026-10-01" }).findings.some((x) => x.check === "cluster.version_eol"));
  });
  test("events, CronJob hygiene and PersistentVolumes", () => {
    const ev = (count) => ({ apiVersion: "v1", kind: "Event", metadata: { name: "e" + count, namespace: "app" }, involvedObject: { kind: "Pod", name: "p" + count }, reason: "BackOff", message: "Back-off restarting failed container", count });
    const cj = (name, spec) => ({ apiVersion: "batch/v1", kind: "CronJob", metadata: { name, namespace: "app" }, spec: { schedule: "* * * * *", jobTemplate: { spec: { template: { spec: good() } } }, ...spec } });
    const r = run([ev(5), ev(4), cj("loose", {}), cj("tight", { concurrencyPolicy: "Forbid" }), { apiVersion: "v1", kind: "PersistentVolume", metadata: { name: "pv" }, spec: { hostPath: { path: "/data" } } }]);
    assert.equal(by(r, "cluster.events")[0].evidenceCount, 1);
    assert.equal(by(r, "cluster.cronjob_hygiene")[0].evidence[0].cronJob, "loose");
    assert.equal(by(r, "cluster.pv")[0].evidence[0].hostPath, "/data");
  });
  test("kube-bench FAIL / WARN map to CIS ids with severity by node type", () => {
    const r = analyze(parseInput([{ name: "kb.json", text: KUBE_BENCH }]));
    const kb = by(r, "kubebench");
    const get = (id) => kb.find((f) => f.controls[0].id === id);
    assert.equal(get("1.2.1").severity, "high"); assert.equal(get("4.2.1").severity, "medium"); assert.equal(get("5.1.1").severity, "high");
    assert.equal(get("4.2.9").severity, "low"); assert.equal(get("4.2.9").confidence, "review");
    assert.ok(!kb.some((f) => f.controls[0].id === "4.2.2"));
    assert.equal(get("4.2.1").recommendation, "Disable anonymous auth");
    assert.deepEqual(r.summary.kubeBench, { pass: 1, fail: 3, warn: 1, info: 0 });
  });
});

group("k8saudit: contract", () => {
  test("selfTest passes", () => {
    const st = selfTest();
    assert.ok(st.pass, "failed: " + st.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
  test("analyze is byte-identical across runs and file orders", () => {
    const ex = exampleDataset();
    const a = JSON.stringify(analyze(parseInput(ex.files), { eol: ex.eol }));
    assert.equal(a, JSON.stringify(analyze(parseInput(ex.files), { eol: ex.eol })));
    const rev = analyze(parseInput(ex.files.slice().reverse()), { eol: ex.eol });
    assert.equal(JSON.stringify(rev.findings), JSON.stringify(JSON.parse(a).findings));
  });
  test("example matches the brief: 3 namespaces, 8 workloads, calico info, cluster-admin user + group, :latest, kube-bench 2 FAIL", () => {
    const ex = exampleDataset();
    const r = analyze(parseInput(ex.files), { eol: ex.eol });
    assert.equal(r.summary.namespaces, 3); assert.equal(r.summary.workloads, 8);
    assert.equal(r.summary.kubeBench.fail, 2);
    assert.ok(by(r, "pod.image_tag")[0].evidence.some((e) => e.image === "redis:latest"));
    assert.equal(by(r, "rbac.cluster_admin").length, 2);
  });
  test("every finding carries controls, confidence, recommendation and capped evidence", () => {
    const ex = exampleDataset();
    const r = analyze(parseInput(ex.files), { eol: ex.eol });
    for (const f of r.findings) {
      assert.ok(f.controls.length >= 1 && f.recommendation && ["confirmed", "likely", "review"].includes(f.confidence), f.id);
      assert.ok(f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length, f.id);
      assert.ok(f.assets.some((a) => a.type === "ASSET" && a.data && a.data.kind === "k8s-cluster"), f.id);
    }
    const wl = r.findings.flatMap((f) => f.assets).find((a) => a.data && a.data.kind === "k8s-workload");
    assert.ok(wl.data.namespace && Array.isArray(wl.data.images) && Array.isArray(wl.data.exposure));
  });
  test("progress callback is optional and called", () => {
    const calls = [];
    analyze(parseInput(exampleDataset().files), {}, { progress: (i, n, l) => calls.push(l) });
    assert.ok(calls.includes("pod security"));
    analyze(parseInput(exampleDataset().files), {}, {});
  });
  test("empty input: no findings, no throw, kinds skipped", () => {
    const r = analyze(parseInput(""));
    assert.equal(r.findings.length, 0); assert.ok(r.skipped.length > 5);
  });
  test("findingsToCsv header and row shape", () => {
    const csv = findingsToCsv(analyze(parseInput(exampleDataset().files)).findings);
    const lines = csv.trim().split("\n");
    assert.equal(lines[0], "severity,confidence,category,check,title,description,recommendation,controls,evidenceCount,assets,path");
    assert.ok(lines.length > 10);
    assert.equal(findingsToCsv([]).trim(), lines[0]);
  });
  test("RBAC matrix and workload CSVs", () => {
    const r = analyze(parseInput(exampleDataset().files));
    const m = rbacMatrixCsv(r.tables.subjects).split("\n");
    assert.ok(m[0].startsWith("kind,name,namespace,scope,clusterAdmin,source,wildcard (*) access,read secrets"));
    assert.ok(m.some((l) => l.startsWith("ServiceAccount,default,web") && l.includes("app") === false && l.includes("ns web")));
    assert.ok(workloadsToCsv(r.tables.workloads).startsWith("namespace,kind,name,replicas,images,serviceAccount,privileged"));
  });
  test("remediation YAML: default-deny for flagged namespaces and securityContext patches, parseable", async () => {
    const r = analyze(parseInput(exampleDataset().files));
    const y = remediationYaml(r);
    assert.ok(y.includes("name: default-deny-ingress-egress\n  namespace: web"));
    assert.ok(y.includes("# web/Deployment/frontend") && y.includes("privileged: false"));
    assert.ok(!y.includes("calico-node"));
    const { parseYamlSubset } = await import("../../public/js/ingest/parse.js");
    const docs = parseYamlSubset(y);
    assert.ok(Array.isArray(docs) && docs.some((d) => d && d.kind === "NetworkPolicy"));
  });
  test("summary text lists findings and skipped checks", () => {
    const t = summaryText(analyze(parseInput(exampleDataset().files)));
    assert.ok(t.includes("Kubernetes Audit summary") && t.includes("Skipped checks:") && t.includes("[critical/"));
  });
  test("a resource whose kind is a prototype member name does not crash the audit", () => {
    for (const kind of ["constructor", "__proto__", "toString", "hasOwnProperty"]) {
      const obj = { apiVersion: "v1", kind, metadata: { name: "x", namespace: "default" } };
      const rep = analyze(parseInput([{ name: "dump.json", text: list([obj, ns("default")]) }]), { now: "2026-10-01" });
      assert.ok(rep && Array.isArray(rep.findings), "analyze returned a report for kind=" + kind);
    }
  });
});
