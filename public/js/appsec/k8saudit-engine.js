// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Kubernetes Audit engine (k8saudit). Pure logic: no DOM, no network, no clock.
//
// Audits the LIVE state of a cluster from a dump: `kubectl get ... -A -o json|yaml`
// (List documents, multi-document YAML, single objects), kube-bench JSON, optional
// `kubectl auth can-i --list` text and `kubectl get --raw /version` JSON. The focus
// is cluster-wide relationships: the RBAC graph (bindings -> roles -> rules, incl.
// aggregated ClusterRoles), namespace isolation (NetworkPolicy coverage, Pod
// Security Admission labels) and workload-to-service exposure chains.
//
// Secret `data` / `stringData` values are dropped at parse time; only key names are
// kept. ConfigMap values are dropped the same way. Nothing in a finding carries a
// secret value.
//
// Deterministic: same input -> byte-identical output. Everything is sorted by
// (namespace, kind, name); the only clock is `opts.now`.

import { sniff, parseYamlSubset } from "../ingest/parse.js";

export const TOOL_ID = "k8saudit";
export const VERSION = "1.0.0";

export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Tunable settings; the UI renders these as the settings panel. */
export const DEFAULTS = {
  clusterName: "cluster",          // name of the cluster ASSET in the Security Graph
  allowedRegistries: [],           // image registries the organisation allows (blank = report registries in use for review)
  authenticatedCritical: true,     // cluster-admin bound to system:authenticated / system:unauthenticated is critical (else high)
  sharedSecretWorkloads: 3,        // a Secret mounted into this many workloads is a shared blast radius
  eventRepeatCount: 5,             // BackOff / Failed events with at least this count are reported
  kubeletSkewMinors: 2,            // kubelet minor versions behind the control plane before it is reported
  assumeComplete: false,           // the dump holds every kind: an absent kind means none exist (else checks needing it are skipped)
  now: null,                       // ISO reference date (EOL checks); default = newest timestamp in the dump
  eol: null,                       // endoflife.date entry for "kubernetes" (passed in by the UI from /data/feeds/eol-products.json)
};

/** Logical fields read from the dump (object paths), for the kit's COLUMNS contract. */
export const COLUMNS = {
  kind: ["kind"], name: ["metadata.name"], namespace: ["metadata.namespace"], uid: ["metadata.uid"],
  labels: ["metadata.labels"], podTemplate: ["spec.template.spec", "spec.jobTemplate.spec.template.spec", "spec"],
  rules: ["rules"], subjects: ["subjects"], roleRef: ["roleRef"],
};

/** Kinds the engine understands (anything else is kept in the inventory but not analysed). */
export const KINDS = [
  "Namespace", "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Service", "Ingress",
  "NetworkPolicy", "ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "Secret", "ConfigMap",
  "Node", "PersistentVolume", "PodSecurityPolicy", "Event",
];
const WORKLOAD_KINDS = ["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet", "Pod"];
const SYSTEM_NS = ["kube-system", "kube-public", "kube-node-lease"];
const SYSTEM_GROUPS = ["system:authenticated", "system:unauthenticated", "system:serviceaccounts"];
const BUILTIN_ROLES = /^(system:|cluster-admin$|admin$|edit$|view$)/;
/** Well-known kube-system DaemonSets / CNI / CSI / agents whose host access is expected. */
export const KNOWN_SYSTEM = /^(calico|cilium|kube-proxy|aws-node|ebs-csi|efs-csi|azure-|gke-|fluent-bit|fluentd|datadog|falco|coredns|kube-dns|metrics-server|node-local-dns|konnectivity|csi-|weave|flannel|antrea|vpc-cni|aws-load-balancer|nvidia-|kube-apiserver|kube-controller-manager|kube-scheduler|etcd)/;
/** Registries a kube-system workload is expected to pull from. */
const KNOWN_SYSTEM_REGISTRIES = /^(registry\.k8s\.io|k8s\.gcr\.io|gcr\.io|quay\.io|public\.ecr\.aws|[0-9]+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com|mcr\.microsoft\.com|docker\.io\/(calico|rancher|weaveworks|flannel|cilium|library)|ghcr\.io\/(cilium|fluent)|amazon|602401143452\.dkr)/;
const SENSITIVE_HOSTPATH = [/^\/$/, /^\/var\/run\/docker\.sock$/, /^\/run\/containerd/, /^\/var\/run\/crio/, /^\/etc(\/|$)/, /^\/proc(\/|$)/, /^\/sys(\/|$)/, /^\/root(\/|$)/, /^\/var\/lib\/kubelet/, /^\/var\/lib\/docker/, /^\/dev(\/|$)/, /^\/boot(\/|$)/];
const DANGEROUS_CAPS = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "DAC_OVERRIDE", "SYS_RAWIO", "SYS_BOOT", "BPF", "PERFMON", "ALL"];
const CRED_KEY = /(passw(or)?d|secret|token|api[_-]?key|apikey|private[_-]?key|credential|access[_-]?key)/i;
const SECRET_NAME = /(token|secret|passw|credential|key)/i;

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------
const CIS = (id) => ({ framework: "CIS Kubernetes Benchmark v1.9", id });
const NSA = (id) => ({ framework: "NSA/CISA Kubernetes Hardening Guide v1.2", id });
const PSS = (id) => ({ framework: "Kubernetes Pod Security Standards", id });
const MITRE = (id) => ({ framework: "MITRE ATT&CK", id });
const NIST = (id) => ({ framework: "NIST 800-53", id });

/** Every detection with its controls and the kinds it needs in the dump (skip-and-report otherwise). */
export const DETECTIONS = [
  { check: "rbac.cluster_admin", category: "rbac", needs: ["ClusterRoleBinding", "RoleBinding"], controls: [CIS("5.1.1"), NSA("Authentication and authorization"), MITRE("T1078.001"), NIST("AC-6")] },
  { check: "rbac.wildcard", category: "rbac", needs: ["Role", "ClusterRole"], controls: [CIS("5.1.3"), NIST("AC-6")] },
  { check: "rbac.dangerous_role", category: "rbac", needs: ["Role", "ClusterRole"], controls: [CIS("5.1.2"), CIS("5.1.4"), CIS("5.1.8"), MITRE("T1613"), NIST("AC-6")] },
  { check: "rbac.orphan_binding", category: "rbac", needs: ["RoleBinding", "ClusterRoleBinding"], controls: [CIS("5.1.1"), NIST("AC-6")] },
  { check: "rbac.default_sa_bound", category: "rbac", needs: ["RoleBinding", "ClusterRoleBinding"], controls: [CIS("5.1.5"), MITRE("T1078.001"), NIST("AC-6")] },
  { check: "rbac.default_sa_automount", category: "rbac", needs: ["ServiceAccount"], controls: [CIS("5.1.5"), MITRE("T1552.007"), NIST("AC-6")] },
  { check: "rbac.automount_unneeded", category: "rbac", needs: ["ServiceAccount", "RoleBinding", "ClusterRoleBinding"], controls: [CIS("5.1.6"), MITRE("T1552.007"), NIST("AC-6")] },
  { check: "pod.privileged", category: "pod-security", needs: WORKLOAD_KINDS, controls: [CIS("5.2.2"), PSS("baseline: privileged containers"), NSA("Kubernetes Pod security"), MITRE("T1611"), NIST("CM-6")] },
  { check: "pod.host_namespaces", category: "pod-security", needs: WORKLOAD_KINDS, controls: [CIS("5.2.3"), CIS("5.2.4"), CIS("5.2.5"), PSS("baseline: host namespaces"), MITRE("T1611"), NIST("CM-6")] },
  { check: "pod.privilege_escalation", category: "pod-security", needs: WORKLOAD_KINDS, controls: [CIS("5.2.6"), PSS("restricted: privilege escalation"), NIST("CM-6")] },
  { check: "pod.run_as_root", category: "pod-security", needs: WORKLOAD_KINDS, controls: [CIS("5.2.7"), PSS("restricted: running as non-root"), NSA("Kubernetes Pod security"), NIST("AC-6")] },
  { check: "pod.net_raw", category: "pod-security", needs: WORKLOAD_KINDS, controls: [CIS("5.2.8"), PSS("restricted: capabilities"), NIST("CM-6")] },
  { check: "pod.added_capabilities", category: "pod-security", needs: WORKLOAD_KINDS, controls: [CIS("5.2.9"), PSS("baseline: capabilities"), MITRE("T1611"), NIST("CM-6")] },
  { check: "pod.hostpath", category: "pod-security", needs: WORKLOAD_KINDS, controls: [CIS("5.2.12"), PSS("baseline: hostPath volumes"), MITRE("T1611"), NIST("CM-6")] },
  { check: "pod.hostport", category: "pod-security", needs: WORKLOAD_KINDS, controls: [CIS("5.2.13"), PSS("baseline: hostPorts"), NIST("SC-7")] },
  { check: "pod.windows_hostprocess", category: "pod-security", needs: WORKLOAD_KINDS, controls: [CIS("5.2.11"), PSS("baseline: HostProcess"), MITRE("T1611")] },
  { check: "pod.no_limits", category: "pod-security", needs: WORKLOAD_KINDS, controls: [NSA("Kubernetes Pod security"), NIST("CM-6")] },
  { check: "pod.image_tag", category: "pod-security", needs: WORKLOAD_KINDS, controls: [NSA("Kubernetes Pod security"), NIST("CM-6")] },
  { check: "pod.image_registry", category: "pod-security", needs: WORKLOAD_KINDS, controls: [NSA("Kubernetes Pod security"), NIST("CM-6")] },
  { check: "pod.secret_env", category: "secrets", needs: WORKLOAD_KINDS, controls: [CIS("5.4.1"), NIST("SC-28")] },
  { check: "pod.literal_secret_env", category: "secrets", needs: WORKLOAD_KINDS, controls: [CIS("5.4.1"), MITRE("T1552"), NIST("SC-28")] },
  { check: "pod.no_probes", category: "pod-security", needs: ["Deployment", "StatefulSet", "DaemonSet"], controls: [NSA("Kubernetes Pod security"), NIST("CM-6")] },
  { check: "pod.no_seccomp", category: "pod-security", needs: WORKLOAD_KINDS, controls: [CIS("5.7.2"), PSS("restricted: seccomp"), NIST("CM-6")] },
  { check: "pod.writable_rootfs", category: "pod-security", needs: WORKLOAD_KINDS, controls: [NSA("Kubernetes Pod security"), CIS("5.7.3"), NIST("CM-6")] },
  { check: "pod.shared_process_ns", category: "pod-security", needs: WORKLOAD_KINDS, controls: [CIS("5.7.3"), NIST("CM-6")] },
  { check: "pod.sysctls", category: "pod-security", needs: WORKLOAD_KINDS, controls: [PSS("baseline: sysctls"), NIST("CM-6")] },
  { check: "ns.psa_labels", category: "pod-security", needs: ["Namespace"], controls: [CIS("5.2.1"), PSS("enforce label"), NIST("CM-6")] },
  { check: "ns.legacy_psp", category: "pod-security", needs: ["PodSecurityPolicy"], controls: [CIS("5.2.1"), NIST("CM-6")] },
  { check: "net.no_policy", category: "network", needs: ["NetworkPolicy"], controls: [CIS("5.3.2"), NSA("Network separation and hardening"), NIST("SC-7")] },
  { check: "net.no_default_deny", category: "network", needs: ["NetworkPolicy"], controls: [CIS("5.3.2"), NSA("Network separation and hardening"), NIST("SC-7")] },
  { check: "net.policy_selects_nothing", category: "network", needs: ["NetworkPolicy"], controls: [CIS("5.3.2"), NIST("SC-7")] },
  { check: "net.exposed_privileged", category: "network", needs: ["Service"], controls: [CIS("5.2.2"), NSA("Network separation and hardening"), MITRE("T1611"), NIST("SC-7")] },
  { check: "net.ingress_no_tls", category: "network", needs: ["Ingress"], controls: [NSA("Network separation and hardening"), NIST("SC-8")] },
  { check: "net.ingress_ssl_redirect_off", category: "network", needs: ["Ingress"], controls: [NSA("Network separation and hardening"), NIST("SC-8")] },
  { check: "net.service_no_endpoints", category: "network", needs: ["Service"], controls: [NIST("CM-6")] },
  { check: "secret.opaque_default_ns", category: "secrets", needs: ["Secret"], controls: [CIS("5.7.4"), NIST("SC-28")] },
  { check: "secret.shared", category: "secrets", needs: ["Secret"], controls: [CIS("5.4.2"), NIST("SC-28")] },
  { check: "secret.sa_token", category: "secrets", needs: ["Secret"], controls: [CIS("5.1.6"), MITRE("T1552.007"), NIST("SC-28")] },
  { check: "secret.dockerconfig_spread", category: "secrets", needs: ["Secret"], controls: [CIS("5.4.2"), NIST("SC-28")] },
  { check: "configmap.credential_keys", category: "secrets", needs: ["ConfigMap"], controls: [CIS("5.4.1"), MITRE("T1552"), NIST("SC-28")] },
  { check: "cluster.default_namespace", category: "cluster", needs: WORKLOAD_KINDS, controls: [CIS("5.7.4"), CIS("5.7.1"), NIST("CM-6")] },
  { check: "cluster.system_unknown_image", category: "cluster", needs: WORKLOAD_KINDS, controls: [NSA("Kubernetes Pod security"), MITRE("T1610"), NIST("CM-6")] },
  { check: "cluster.node_health", category: "cluster", needs: ["Node"], controls: [NIST("CM-6")] },
  { check: "cluster.kubelet_skew", category: "cluster", needs: ["Node"], controls: [NSA("Upgrading and application security practices"), NIST("SI-2")] },
  { check: "cluster.version_eol", category: "cluster", needs: ["version"], controls: [NSA("Upgrading and application security practices"), NIST("SI-2")] },
  { check: "cluster.events", category: "cluster", needs: ["Event"], controls: [NIST("SI-4")] },
  { check: "cluster.cronjob_hygiene", category: "cluster", needs: ["CronJob"], controls: [NIST("CM-6")] },
  { check: "cluster.pv", category: "cluster", needs: ["PersistentVolume"], controls: [CIS("5.2.12"), NIST("CM-6")] },
  { check: "kubebench", category: "kube-bench", needs: ["kube-bench"], controls: [CIS("kube-bench")] },
  { check: "cani", category: "rbac", needs: ["can-i"], controls: [CIS("5.1.1"), NIST("AC-6")] },
];

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
const str = (v) => (v == null ? "" : String(v));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const uniq = (arr) => Array.from(new Set(arr)).sort();
const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);
const arr = (v) => (Array.isArray(v) ? v : []);
const get = (o, path) => path.split(".").reduce((a, k) => (a == null ? undefined : a[k]), o);
const ref = (o) => (o.metadata.namespace ? o.metadata.namespace + "/" : "") + o.kind + "/" + o.metadata.name;
const byRef = (a, b) => cmp(str(a.metadata.namespace), str(b.metadata.namespace)) || cmp(a.kind, b.kind) || cmp(a.metadata.name, b.metadata.name);
const sevMax = (a, b) => (SEV_RANK[a] >= SEV_RANK[b] ? a : b);
const mask = (v) => { const s = str(v); return s.length <= 4 ? "****" : s.slice(0, 2) + "*".repeat(Math.min(12, s.length - 4)) + s.slice(-2); };

/** Parse "v1.28.3-eks-abc" -> { major, minor, patch, text } or null. */
export function parseVersion(v) {
  const m = /v?(\d+)\.(\d+)(?:\.(\d+))?/.exec(str(v));
  return m ? { major: +m[1], minor: +m[2], patch: m[3] == null ? null : +m[3], text: str(v) } : null;
}

/** Split an image reference into registry / repository / tag / digest. */
export function parseImage(image) {
  let s = str(image).trim(), digest = null, tag = null;
  const at = s.indexOf("@");
  if (at >= 0) { digest = s.slice(at + 1); s = s.slice(0, at); }
  const slash = s.indexOf("/");
  let registry = "docker.io", rest = s;
  if (slash > 0) {
    const first = s.slice(0, slash);
    if (first.includes(".") || first.includes(":") || first === "localhost") { registry = first; rest = s.slice(slash + 1); }
  }
  const colon = rest.lastIndexOf(":");
  if (colon > 0 && !rest.slice(colon + 1).includes("/")) { tag = rest.slice(colon + 1); rest = rest.slice(0, colon); }
  const repository = registry === "docker.io" && !rest.includes("/") ? "library/" + rest : rest;
  return { image: str(image).trim(), registry, repository, tag, digest, pinned: !!digest, floating: !digest && (!tag || tag === "latest") };
}

/** Label selector ({ matchLabels, matchExpressions } or a plain map) against a label map. */
export function selectorMatches(selector, labels) {
  if (selector == null) return false;
  labels = labels || {};
  const ml = selector.matchLabels || selector.matchExpressions ? selector.matchLabels || {} : selector;
  for (const [k, v] of Object.entries(ml || {})) if (str(labels[k]) !== str(v)) return false;
  for (const e of arr(selector.matchExpressions)) {
    const has = Object.prototype.hasOwnProperty.call(labels, e.key), v = str(labels[e.key]);
    const vals = arr(e.values).map(str);
    if (e.operator === "In" && !(has && vals.includes(v))) return false;
    if (e.operator === "NotIn" && has && vals.includes(v)) return false;
    if (e.operator === "Exists" && !has) return false;
    if (e.operator === "DoesNotExist" && has) return false;
  }
  return true;
}
const emptySelector = (sel) => !sel || (!Object.keys(sel.matchLabels || {}).length && !arr(sel.matchExpressions).length && !Object.keys(sel).filter((k) => k !== "matchLabels" && k !== "matchExpressions").length);

/** Minimal YAML re-serialiser for evidence snippets (sorted keys, 2-space indent). */
export function toYaml(v, indent = 0) {
  const pad = " ".repeat(indent);
  if (Array.isArray(v)) {
    if (!v.length) return pad + "[]";
    return v.map((x) => (isObj(x) || Array.isArray(x) ? pad + "-\n" + toYaml(x, indent + 2) : pad + "- " + scalar(x))).join("\n");
  }
  if (isObj(v)) {
    const keys = Object.keys(v).sort();
    if (!keys.length) return pad + "{}";
    return keys.map((k) => {
      const x = v[k];
      const key = /^[A-Za-z0-9_./-]+$/.test(k) ? k : JSON.stringify(k);
      if (isObj(x) || Array.isArray(x)) return (Object.keys(x).length ? pad + key + ":\n" + toYaml(x, indent + 2) : pad + key + ": " + (Array.isArray(x) ? "[]" : "{}"));
      return pad + key + ": " + scalar(x);
    }).join("\n");
  }
  return pad + scalar(v);
}
function scalar(x) {
  if (x === null || x === undefined) return "null";
  if (typeof x === "boolean" || typeof x === "number") return String(x);
  const s = String(x);
  return /^[A-Za-z0-9_./:@+-][A-Za-z0-9 _./:@+=,-]*$/.test(s) && !/^(true|false|null|yes|no|on|off|~)$/i.test(s) && !/^[-+]?\d/.test(s) ? s : JSON.stringify(s);
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------
/** Normalise one API object: strip secret values, managedFields and last-applied annotations. Returns null when it is not a K8s object. */
export function normalizeObject(o) {
  if (!isObj(o) || typeof o.kind !== "string" || !isObj(o.metadata) && o.kind !== "Event") return null;
  const md = isObj(o.metadata) ? o.metadata : {};
  if (!md.name && o.kind !== "Event") return null;
  const out = { ...o, metadata: { ...md } };
  delete out.metadata.managedFields;
  if (isObj(out.metadata.annotations)) {
    const a = { ...out.metadata.annotations };
    delete a["kubectl.kubernetes.io/last-applied-configuration"];
    out.metadata.annotations = a;
  }
  if (out.kind === "Secret") {
    out.dataKeys = uniq([...Object.keys(isObj(o.data) ? o.data : {}), ...Object.keys(isObj(o.stringData) ? o.stringData : {})]);
    delete out.data; delete out.stringData;
  } else if (out.kind === "ConfigMap") {
    out.dataKeys = uniq([...Object.keys(isObj(o.data) ? o.data : {}), ...Object.keys(isObj(o.binaryData) ? o.binaryData : {})]);
    delete out.data; delete out.binaryData;
  }
  if (!out.metadata.namespace && out.involvedObject && out.involvedObject.namespace) out.metadata.namespace = out.involvedObject.namespace;
  return out;
}

const looksKubeBench = (v) => (isObj(v) && Array.isArray(v.Controls)) || (Array.isArray(v) && v.length && isObj(v[0]) && Array.isArray(v[0].Controls));
const looksVersion = (v) => isObj(v) && (typeof v.gitVersion === "string" && "major" in v || isObj(v.serverVersion) && typeof v.serverVersion.gitVersion === "string");
const CANI_HEADER = /^Resources\s+Non-Resource URLs\s+Resource Names\s+Verbs\s*$/m;

function collectObjects(v, out) {
  if (Array.isArray(v)) { for (const x of v) collectObjects(x, out); return; }
  if (!isObj(v)) return;
  if ((v.kind === "List" || /List$/.test(str(v.kind))) && Array.isArray(v.items)) { for (const x of v.items) collectObjects(x, out); return; }
  const n = normalizeObject(v);
  if (n) out.push(n);
}

/** Parse `kubectl auth can-i --list` text into rows. The subject is taken from the file name (e.g. can-i-alice.txt -> alice). */
export function parseCanI(text, name = "") {
  const rows = [];
  const lines = str(text).split(/\r?\n/);
  const hi = lines.findIndex((l) => /^Resources\s+Non-Resource URLs/.test(l));
  if (hi < 0) return null;
  const head = lines[hi];
  const cols = ["Resources", "Non-Resource URLs", "Resource Names", "Verbs"].map((c) => head.indexOf(c));
  for (const l of lines.slice(hi + 1)) {
    if (!l.trim()) continue;
    const cut = (i) => l.slice(cols[i], i + 1 < cols.length ? cols[i + 1] : undefined).trim();
    const list = (s) => s.replace(/^\[|\]$/g, "").split(/\s+/).filter(Boolean);
    rows.push({ resource: cut(0), nonResourceURLs: list(cut(1)), resourceNames: list(cut(2)), verbs: list(cut(3)) });
  }
  const subject = str(name).replace(/\.[a-z]+$/i, "").replace(/^(kubectl[-_ ])?(auth[-_ ])?can[-_ ]?i[-_ ]?(list)?[-_ ]?/i, "").trim() || "subject";
  return { subject, rows };
}

/** Classify + parse one file's text. */
export function parseFile(text, name = "input") {
  const t = str(text).replace(/^﻿/, "");
  const file = { name, kind: "unknown", objects: 0, kinds: Object.create(null), confidence: 0 };
  const res = { file, objects: [], kubeBench: null, canI: null, version: null, error: null };
  if (!t.trim()) { res.error = "empty file"; return res; }
  if (CANI_HEADER.test(t)) { res.canI = parseCanI(t, name); file.kind = "can-i"; file.confidence = 1; file.objects = res.canI.rows.length; return res; }
  const fmt = sniff(t).format;
  let v;
  if (fmt === "json" || /^\s*[[{]/.test(t)) { try { v = JSON.parse(t); } catch (e) { res.error = "invalid JSON: " + e.message; return res; } }
  else if (fmt === "yaml" || /^(apiVersion|kind|items):/m.test(t)) { try { v = parseYamlSubset(t); } catch (e) { res.error = e.message; return res; } }
  else { res.error = "not JSON, YAML, kube-bench or can-i output (" + fmt + ")"; return res; }
  if (looksKubeBench(v)) {
    const wrappers = Array.isArray(v) ? v : [v];
    res.kubeBench = { Controls: wrappers.flatMap((w) => arr(w.Controls)) };
    file.kind = "kube-bench"; file.confidence = 1; file.objects = res.kubeBench.Controls.length;
    return res;
  }
  if (looksVersion(v)) {
    const sv = v.serverVersion || v;
    res.version = { gitVersion: str(sv.gitVersion), major: str(sv.major), minor: str(sv.minor), platform: str(sv.platform), gitCommit: str(sv.gitCommit), buildDate: str(sv.buildDate) };
    file.kind = "version"; file.confidence = 1; file.objects = 1;
    return res;
  }
  collectObjects(v, res.objects);
  if (res.objects.length) {
    file.kind = "k8s"; file.confidence = 1; file.objects = res.objects.length;
    for (const o of res.objects) file.kinds[o.kind] = (file.kinds[o.kind] || 0) + 1;
  } else res.error = "no Kubernetes objects found";
  return res;
}

/**
 * Parse one text or many files ({name, text}[]) into a normalised dataset.
 * Objects are de-duplicated by metadata.uid (else namespace/kind/name) across files
 * and sorted by (namespace, kind, name). Secret values never survive this step.
 */
export function parseInput(input) {
  const files = Array.isArray(input) ? input : [{ name: "input", text: input }];
  const seen = new Map(), skipped = [], meta = [], canI = [];
  let kubeBench = null, version = null, duplicates = 0;
  for (const f of files) {
    const r = parseFile(f && f.text != null ? f.text : f, f && f.name ? f.name : "input");
    meta.push(r.file);
    if (r.error) { skipped.push({ check: "parse", file: r.file.name, reason: r.error }); continue; }
    if (r.kubeBench) kubeBench = kubeBench ? { Controls: kubeBench.Controls.concat(r.kubeBench.Controls) } : r.kubeBench;
    if (r.version) version = r.version;
    if (r.canI) canI.push(r.canI);
    for (const o of r.objects) {
      const key = o.metadata.uid ? "uid:" + o.metadata.uid : ref(o);
      if (seen.has(key)) { duplicates++; continue; }
      seen.set(key, o);
    }
  }
  const objects = Array.from(seen.values()).sort(byRef);
  const kinds = Object.create(null);
  for (const o of objects) kinds[o.kind] = (kinds[o.kind] || 0) + 1;
  canI.sort((a, b) => cmp(a.subject, b.subject));
  const stats = { files: files.length, objects: objects.length, duplicates, kinds: Object.fromEntries(Object.keys(kinds).sort().map((k) => [k, kinds[k]])), kubeBench: kubeBench ? kubeBench.Controls.length : 0, canI: canI.length, version: version ? version.gitVersion : null };
  return { objects, kubeBench, canI, version, skipped, stats, files: meta };
}

// ---------------------------------------------------------------------------
// RBAC model
// ---------------------------------------------------------------------------
/** Built-in cluster-admin rules (used when the ClusterRole itself is not in the dump). */
const CLUSTER_ADMIN_RULES = [{ apiGroups: ["*"], resources: ["*"], verbs: ["*"] }, { nonResourceURLs: ["*"], verbs: ["*"] }];
const WORKLOAD_RESOURCES = [["", "pods"], ["", "replicationcontrollers"], ["apps", "deployments"], ["apps", "daemonsets"], ["apps", "statefulsets"], ["apps", "replicasets"], ["batch", "jobs"], ["batch", "cronjobs"]];
// The default user-facing ClusterRoles, trimmed to the rules the DANGEROUS catalogue tests. An export
// rarely includes them, yet "edit" / "admin" bindings are the most common way people get these powers.
const EDIT_RULES = [
  { apiGroups: [""], resources: ["secrets"], verbs: ["get", "list", "watch", "create", "update", "patch", "delete"] },
  { apiGroups: [""], resources: ["pods", "pods/exec", "pods/attach", "pods/portforward", "pods/proxy", "replicationcontrollers"], verbs: ["get", "list", "watch", "create", "update", "patch", "delete"] },
  { apiGroups: ["apps"], resources: ["deployments", "daemonsets", "statefulsets", "replicasets"], verbs: ["get", "list", "watch", "create", "update", "patch", "delete"] },
  { apiGroups: ["batch"], resources: ["jobs", "cronjobs"], verbs: ["get", "list", "watch", "create", "update", "patch", "delete"] },
  { apiGroups: [""], resources: ["serviceaccounts"], verbs: ["impersonate"] },
];
const BUILTIN_RULES = {
  edit: EDIT_RULES,
  admin: EDIT_RULES.concat([{ apiGroups: ["rbac.authorization.k8s.io"], resources: ["roles", "rolebindings"], verbs: ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"] }]),
};

/** Dangerous permission catalogue: key, label, severity, rule test. */
export const DANGEROUS = [
  { key: "wildcard", label: "wildcard (*) access", sev: "high", test: (r) => arr(r.verbs).includes("*") && arr(r.resources).includes("*") },
  { key: "secrets", label: "read secrets", sev: "high", test: (r) => allows(r, "", "secrets", ["get", "list", "watch"]) },
  { key: "create-pods", label: "create pods / workloads", sev: "medium", test: (r) => WORKLOAD_RESOURCES.some(([g, res]) => allows(r, g, res, ["create"])) },
  { key: "pods-exec", label: "pods/exec", sev: "high", test: (r) => allows(r, "", "pods/exec", ["create", "get"]) },
  { key: "pods-attach", label: "pods/attach", sev: "medium", test: (r) => allows(r, "", "pods/attach", ["create", "get"]) },
  { key: "pods-portforward", label: "pods/portforward", sev: "medium", test: (r) => allows(r, "", "pods/portforward", ["create", "get"]) },
  { key: "impersonate", label: "impersonate", sev: "high", test: (r) => ["users", "groups", "serviceaccounts", "uids"].some((res) => allows(r, "", res, ["impersonate"])) },
  { key: "escalate", label: "escalate roles", sev: "high", test: (r) => ["roles", "clusterroles"].some((res) => allows(r, "rbac.authorization.k8s.io", res, ["escalate"])) },
  { key: "bind", label: "bind roles", sev: "high", test: (r) => ["roles", "clusterroles"].some((res) => allows(r, "rbac.authorization.k8s.io", res, ["bind"])) },
  { key: "rbac-write", label: "write RBAC objects", sev: "high", test: (r) => ["roles", "clusterroles", "rolebindings", "clusterrolebindings"].some((res) => allows(r, "rbac.authorization.k8s.io", res, ["create", "update", "patch"])) },
  { key: "nodes-proxy", label: "nodes/proxy", sev: "high", test: (r) => allows(r, "", "nodes/proxy", ["get", "create"]) },
  { key: "pv-create", label: "create persistentvolumes", sev: "medium", test: (r) => allows(r, "", "persistentvolumes", ["create"]) },
  { key: "sa-token", label: "create serviceaccount tokens", sev: "high", test: (r) => allows(r, "", "serviceaccounts/token", ["create"]) },
  { key: "csr-approve", label: "approve CSRs", sev: "high", test: (r) => allows(r, "certificates.k8s.io", "certificatesigningrequests/approval", ["update", "patch"]) },
  { key: "webhooks", label: "write admission webhooks", sev: "high", test: (r) => ["validatingwebhookconfigurations", "mutatingwebhookconfigurations"].some((res) => allows(r, "admissionregistration.k8s.io", res, ["create", "update", "patch"])) },
];

function allows(rule, group, resource, verbs) {
  if (!rule) return false;
  const g = arr(rule.apiGroups), rs = arr(rule.resources), vs = arr(rule.verbs);
  if (!rs.length) return false;
  if (!(g.includes("*") || g.includes(group))) return false;
  // RBAC ResourceMatches: "*", the exact "res/sub", or "*/sub". "pods/*" is NOT a wildcard.
  const sub = resource.includes("/") ? resource.slice(resource.indexOf("/") + 1) : "";
  if (!(rs.includes("*") || rs.includes(resource) || (sub && rs.includes("*/" + sub)))) return false;
  return vs.includes("*") || verbs.some((v) => vs.includes(v));
}

/** Dangerous permissions granted by a rule list -> sorted [{key,label,sev,scoped}] (scoped = limited by resourceNames). */
export function dangerousPerms(rules) {
  const out = new Map();
  for (const r of arr(rules)) for (const d of DANGEROUS) {
    if (!d.test(r)) continue;
    const scoped = arr(r.resourceNames).length > 0;
    const prev = out.get(d.key);
    if (!prev || (prev.scoped && !scoped)) out.set(d.key, { key: d.key, label: d.label, sev: d.sev, scoped });
  }
  return Array.from(out.values()).sort((a, b) => cmp(a.key, b.key));
}
const hasWildcard = (r) => arr(r.verbs).includes("*") || arr(r.resources).includes("*") || arr(r.apiGroups).includes("*");
export const isBuiltinRole = (name) => BUILTIN_ROLES.test(str(name));

/** Resolve every Role / ClusterRole's effective rules, expanding aggregationRule label selectors to a fixpoint. */
export function resolveRoles(objects) {
  const roles = new Map();
  for (const o of objects) {
    if (o.kind !== "Role" && o.kind !== "ClusterRole") continue;
    const key = o.kind === "Role" ? o.metadata.namespace + "/Role/" + o.metadata.name : "ClusterRole/" + o.metadata.name;
    roles.set(key, { key, kind: o.kind, name: o.metadata.name, namespace: str(o.metadata.namespace), obj: o, own: arr(o.rules), rules: arr(o.rules), aggregatedFrom: [] });
  }
  const crs = Array.from(roles.values()).filter((r) => r.kind === "ClusterRole");
  for (let pass = 0; pass < 8; pass++) {
    let changed = false;
    for (const r of crs) {
      const sels = arr(r.obj.aggregationRule && r.obj.aggregationRule.clusterRoleSelectors);
      if (!sels.length) continue;
      const from = crs.filter((c) => c !== r && sels.some((s) => selectorMatches(s, c.obj.metadata.labels)));
      const rules = r.own.concat(...from.map((c) => c.rules));
      if (JSON.stringify(rules) !== JSON.stringify(r.rules)) { r.rules = rules; changed = true; }
      r.aggregatedFrom = from.map((c) => c.name).sort();
    }
    if (!changed) break;
  }
  return roles;
}

function roleFor(roles, binding) {
  const rr = binding.roleRef || {};
  const key = rr.kind === "Role" ? binding.metadata.namespace + "/Role/" + rr.name : "ClusterRole/" + rr.name;
  const r = roles.get(key);
  if (r) return { ...r, found: true };
  if (rr.kind !== "Role" && rr.name === "cluster-admin") return { key, kind: "ClusterRole", name: "cluster-admin", rules: CLUSTER_ADMIN_RULES, aggregatedFrom: [], found: false, builtin: true };
  if (rr.kind !== "Role" && BUILTIN_RULES[rr.name]) return { key, kind: "ClusterRole", name: rr.name, rules: BUILTIN_RULES[rr.name], aggregatedFrom: [], found: false, builtin: true };
  return { key, kind: rr.kind || "ClusterRole", name: str(rr.name), rules: [], aggregatedFrom: [], found: false, builtin: isBuiltinRole(rr.name) };
}
export const subjectKey = (s, bindingNs) => (s.kind === "ServiceAccount" ? "ServiceAccount:" + str(s.namespace || bindingNs) + ":" + s.name : str(s.kind) + "::" + str(s.name));

/** Walk bindings -> roles -> rules. Returns { subjects: Map, bindings: [] }. */
export function rbacGraph(objects, roles) {
  const subjects = new Map(), bindings = [];
  for (const b of objects) {
    if (b.kind !== "RoleBinding" && b.kind !== "ClusterRoleBinding") continue;
    const role = roleFor(roles, b);
    const scope = b.kind === "ClusterRoleBinding" ? "cluster" : b.metadata.namespace;
    const perms = dangerousPerms(role.rules);
    const clusterAdmin = role.kind === "ClusterRole" && role.name === "cluster-admin";
    bindings.push({ binding: b, role, scope, perms, clusterAdmin, subjects: arr(b.subjects) });
    for (const s of arr(b.subjects)) {
      if (!s || !s.name) continue;
      const k = subjectKey(s, b.metadata.namespace);
      let row = subjects.get(k);
      if (!row) subjects.set(k, row = { kind: str(s.kind), name: str(s.name), namespace: s.kind === "ServiceAccount" ? str(s.namespace || b.metadata.namespace) : "", roles: [], bindings: [], perms: new Map(), clusterAdmin: false, clusterWide: false });
      row.roles.push(role.kind + "/" + role.name + " @" + scope);
      row.bindings.push(b.kind + "/" + (b.metadata.namespace ? b.metadata.namespace + "/" : "") + b.metadata.name);
      if (clusterAdmin) row.clusterAdmin = row.clusterAdmin || scope === "cluster";
      if (scope === "cluster") row.clusterWide = true;
      for (const p of perms) {
        const label = p.label + (scope === "cluster" ? "" : " (ns " + scope + ")") + (p.scoped ? " [named]" : "");
        if (!row.perms.has(label)) row.perms.set(label, p.sev);
      }
    }
  }
  return { subjects, bindings };
}

// ---------------------------------------------------------------------------
// Workload model
// ---------------------------------------------------------------------------
function podTemplate(o) {
  if (o.kind === "Pod") return { spec: o.spec || {}, labels: o.metadata.labels || {}, annotations: o.metadata.annotations || {}, base: "spec" };
  if (o.kind === "CronJob") { const t = get(o, "spec.jobTemplate.spec.template") || {}; return { spec: t.spec || {}, labels: get(t, "metadata.labels") || {}, annotations: get(t, "metadata.annotations") || {}, base: "spec.jobTemplate.spec.template.spec" }; }
  const t = get(o, "spec.template") || {};
  return { spec: t.spec || {}, labels: get(t, "metadata.labels") || {}, annotations: get(t, "metadata.annotations") || {}, base: "spec.template.spec" };
}

/** Workloads with ReplicaSet / Pod / Job children collapsed into their controllers. */
export function resolveWorkloads(objects) {
  const present = new Set(), byUid = new Set();
  for (const o of objects) { present.add(str(o.metadata.namespace) + "/" + o.kind + "/" + o.metadata.name); if (o.metadata.uid) byUid.add(o.metadata.uid); }
  const has = (ns, kind, name) => present.has(ns + "/" + kind + "/" + name);
  const owned = (o) => {
    const ns = str(o.metadata.namespace);
    for (const r of arr(o.metadata.ownerReferences)) {
      if (r.kind === "Node") return true; // static / mirror pod: its manifest lives on the node
      if (!WORKLOAD_KINDS.includes(r.kind)) continue;
      if ((r.uid && byUid.has(r.uid)) || has(ns, r.kind, r.name)) return true;
      if (r.kind === "ReplicaSet" && has(ns, "Deployment", str(r.name).replace(/-[a-z0-9]{5,10}$/, ""))) return true;
      if (r.kind === "Job" && has(ns, "CronJob", str(r.name).replace(/-\d{6,}$/, ""))) return true;
    }
    return false;
  };
  const out = [];
  for (const o of objects) {
    if (!WORKLOAD_KINDS.includes(o.kind) || owned(o)) continue;
    if (o.kind === "Pod" && /^(Succeeded|Failed)$/.test(str(get(o, "status.phase")))) continue;
    if (o.kind === "ReplicaSet" && get(o, "spec.replicas") === 0) continue; // old rollout revision
    const t = podTemplate(o);
    const containers = [
      ...arr(t.spec.initContainers).map((c, i) => ({ c, path: t.base + ".initContainers[" + i + "]", init: true })),
      ...arr(t.spec.containers).map((c, i) => ({ c, path: t.base + ".containers[" + i + "]", init: false })),
      // `kubectl debug` containers (often privileged): no resources/probes allowed, so treated like init.
      ...arr(t.spec.ephemeralContainers).map((c, i) => ({ c, path: t.base + ".ephemeralContainers[" + i + "]", init: true })),
    ];
    const ns = str(o.metadata.namespace) || "default";
    const replicas = o.kind === "DaemonSet" ? (get(o, "status.desiredNumberScheduled") ?? null) : o.kind === "Pod" || o.kind === "Job" || o.kind === "CronJob" ? 1 : (get(o, "spec.replicas") ?? 1);
    out.push({
      obj: o, kind: o.kind, name: o.metadata.name, namespace: ns, ref: ns + "/" + o.kind + "/" + o.metadata.name,
      spec: t.spec, labels: t.labels, annotations: t.annotations, base: t.base, containers, replicas,
      sa: str(t.spec.serviceAccountName || t.spec.serviceAccount || "default"),
      images: uniq(containers.map((x) => str(x.c.image)).filter(Boolean)),
      system: SYSTEM_NS.includes(ns) && KNOWN_SYSTEM.test(o.metadata.name),
    });
  }
  return out.sort((a, b) => cmp(a.namespace, b.namespace) || cmp(a.kind, b.kind) || cmp(a.name, b.name));
}

/** Per-container posture facts (container securityContext overrides the pod's). */
export function containerFacts(w, c) {
  const sc = c.securityContext || {}, psc = w.spec.securityContext || {};
  const caps = sc.capabilities || {};
  const drop = arr(caps.drop).map((x) => str(x).toUpperCase().replace(/^CAP_/, ""));
  const add = arr(caps.add).map((x) => str(x).toUpperCase().replace(/^CAP_/, ""));
  const uid = sc.runAsUser ?? psc.runAsUser;
  const nonRoot = sc.runAsNonRoot ?? psc.runAsNonRoot;
  const ann = w.annotations["seccomp.security.alpha.kubernetes.io/pod"];
  const seccomp = (sc.seccompProfile || psc.seccompProfile || {}).type || (ann ? (ann === "unconfined" ? "Unconfined" : "RuntimeDefault") : "");
  const lim = (c.resources || {}).limits || {};
  return {
    privileged: sc.privileged === true,
    allowPrivEsc: sc.allowPrivilegeEscalation !== false,
    root: uid === 0 ? "uid0" : nonRoot === true || (typeof uid === "number" && uid > 0) ? "no" : "possible",
    netRawDropped: drop.includes("ALL") || drop.includes("NET_RAW"),
    added: add.filter((x) => x !== "NET_BIND_SERVICE"),
    seccomp,
    readOnlyRoot: sc.readOnlyRootFilesystem === true,
    hostProcess: !!(get(sc, "windowsOptions.hostProcess") || get(psc, "windowsOptions.hostProcess")),
    noLimits: [!lim.cpu && "cpu", !lim.memory && "memory"].filter(Boolean),
    hostPorts: arr(c.ports).filter((p) => p && p.hostPort > 0).map((p) => p.hostPort),
    probes: !!(c.livenessProbe || c.readinessProbe || c.startupProbe),
  };
}

/** Secret names a workload references (volumes, projected volumes, env, envFrom, imagePullSecrets). */
export function secretRefs(w) {
  const s = new Set();
  for (const v of arr(w.spec.volumes)) {
    if (v.secret && v.secret.secretName) s.add(v.secret.secretName);
    for (const src of arr(get(v, "projected.sources"))) if (src.secret && src.secret.name) s.add(src.secret.name);
  }
  for (const { c } of w.containers) {
    for (const e of arr(c.env)) { const n = get(e, "valueFrom.secretKeyRef.name"); if (n) s.add(n); }
    for (const e of arr(c.envFrom)) if (e.secretRef && e.secretRef.name) s.add(e.secretRef.name);
  }
  for (const p of arr(w.spec.imagePullSecrets)) if (p && p.name) s.add(p.name);
  return Array.from(s).sort();
}

/** Literal env values that look like credentials (name matches, value is not a reference or flag). Values are masked. */
export function literalSecretEnv(c) {
  const out = [];
  for (const e of arr(c.env)) {
    if (!e || e.valueFrom || e.value == null) continue;
    const v = str(e.value), n = str(e.name);
    if (!CRED_KEY.test(n) || /(_FILE|_PATH|_DIR|_URL|_URI|_HOST|_PORT|_USER|_USERNAME|_NAME|_ENABLED|_TTL|_TIMEOUT|_EXPIRY|_HEADER|_LENGTH|_TYPE|_MODE)$/i.test(n)) continue;
    if (v.length < 6 || /^\$\(.+\)$/.test(v) || /^(true|false|yes|no|none|null|\*+)$/i.test(v) || /^\d{1,6}$/.test(v) || /^\/[\w./-]+$/.test(v) || /^https?:\/\/[^@]*$/.test(v)) continue;
    out.push({ name: n, masked: mask(v), length: v.length });
  }
  return out;
}

/** Deep copy safe for evidence: env values of credential-looking names redacted. */
function redact(v) {
  if (Array.isArray(v)) return v.map(redact);
  if (!isObj(v)) return v;
  const o = {};
  for (const k of Object.keys(v)) {
    if (k === "env" && Array.isArray(v[k])) o[k] = v[k].map((e) => (isObj(e) && e.value != null && CRED_KEY.test(str(e.name)) ? { ...e, value: "<redacted>" } : redact(e)));
    else o[k] = redact(v[k]);
  }
  return o;
}
/** YAML evidence snippet with credential-looking env values redacted. */
export function snippet(v) { return toYaml(redact(v)); }

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
const BROAD_GROUPS = ["system:authenticated", "system:unauthenticated", "system:serviceaccounts"];
const isBroad = (s) => (s.kind === "Group" && BROAD_GROUPS.includes(s.name)) || (s.kind === "User" && s.name === "system:anonymous");
const SAFE_SYSCTLS = ["kernel.shm_rmid_forced", "net.ipv4.ip_local_port_range", "net.ipv4.ip_unprivileged_port_start", "net.ipv4.tcp_syncookies", "net.ipv4.ping_group_range", "net.ipv4.ip_local_reserved_ports", "net.ipv4.tcp_keepalive_time", "net.ipv4.tcp_fin_timeout", "net.ipv4.tcp_keepalive_intvl", "net.ipv4.tcp_keepalive_probes"];
const EXPO_RANK = { none: 0, ClusterIP: 1, NodePort: 2, LoadBalancer: 3, Ingress: 3 };

function toDataset(input) {
  if (input && Array.isArray(input.objects)) return { kubeBench: null, canI: [], version: null, skipped: [], stats: {}, files: [], ...input };
  if (typeof input === "string") return parseInput(input);
  if (Array.isArray(input)) {
    if (input.length && input.every((x) => x && typeof x === "object" && "text" in x)) return parseInput(input);
    const objs = [];
    collectObjects(input, objs);
    return { objects: objs.sort(byRef), kubeBench: null, canI: [], version: null, skipped: [], stats: { objects: objs.length }, files: [] };
  }
  return { objects: [], kubeBench: null, canI: [], version: null, skipped: [], stats: { objects: 0 }, files: [] };
}

function newestTimestamp(objects) {
  let best = "";
  for (const o of objects) for (const t of [o.metadata.creationTimestamp, o.lastTimestamp, o.eventTime, get(o, "series.lastObservedTime")]) if (typeof t === "string" && /^\d{4}-\d\d-\d\d/.test(t) && t > best) best = t;
  return best || null;
}

function isDefaultDeny(p, type) {
  const types = arr(get(p, "spec.policyTypes"));
  const effTypes = types.length ? types : ["Ingress", ...(get(p, "spec.egress") ? ["Egress"] : [])];
  if (!effTypes.includes(type) || !emptySelector(get(p, "spec.podSelector"))) return false;
  return !arr(get(p, type === "Ingress" ? "spec.ingress" : "spec.egress")).length;
}

/**
 * Analyze a parsed dataset (parseInput output), raw text, files [{name,text}] or an array of API objects.
 * Returns { summary, findings, tables, skipped, meta, remediation }.
 */
export function analyze(input, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  const progress = (i, n, label) => { try { ctx && ctx.progress && ctx.progress(i, n, label); } catch (_) { /* progress is advisory */ } };
  const ds = toDataset(input);
  const objects = ds.objects;
  const cluster = str(o.clusterName).trim() || "cluster";
  const allowed = (Array.isArray(o.allowedRegistries) ? o.allowedRegistries : str(o.allowedRegistries).split(/[\s,]+/)).map((x) => str(x).trim().replace(/\/+$/, "")).filter(Boolean).sort();
  // Null-proto: an object whose `kind` is a prototype member name ("constructor",
  // "__proto__", "toString") would otherwise resolve to an inherited value, and
  // `.push` on it throws -- taking out the whole audit (a malformed/hand-crafted
  // dump or a maliciously named CRD).
  const idx = Object.create(null);
  for (const x of objects) (idx[x.kind] || (idx[x.kind] = [])).push(x);
  const K = (k) => idx[k] || [];
  const has = (k) => K(k).length > 0 || !!o.assumeComplete;
  const skipped = ds.skipped.slice();
  const DET = Object.fromEntries(DETECTIONS.map((d) => [d.check, d]));
  const gate = (check) => {
    const d = DET[check];
    const ok = d.needs.some((k) => (k === "version" ? !!ds.version : k === "kube-bench" ? !!ds.kubeBench : k === "can-i" ? ds.canI.length > 0 : has(k)));
    if (!ok) skipped.push({ check, reason: (["version", "kube-bench", "can-i"].includes(d.needs[0]) ? d.needs[0] + " input not provided" : "no " + d.needs.join(" / ") + " objects in the dump") });
    return ok;
  };
  const now = o.now || newestTimestamp(objects);
  const clusterAsset = { type: "ASSET", name: cluster, data: { kind: "k8s-cluster", version: ds.version ? ds.version.gitVersion : null } };
  const findings = [];

  progress(0, objects.length, "resolving RBAC");
  const roles = resolveRoles(objects);
  const graph = rbacGraph(objects, roles);
  progress(0, objects.length, "resolving workloads");
  const workloads = resolveWorkloads(objects);
  const nsWorkloads = new Map();
  for (const w of workloads) (nsWorkloads.get(w.namespace) || nsWorkloads.set(w.namespace, []).get(w.namespace)).push(w);

  // Exposure: Service selectors -> workloads; Ingress backends -> Services.
  const ingBySvc = new Map();
  for (const ing of K("Ingress")) {
    const names = new Set();
    const dflt = get(ing, "spec.defaultBackend.service.name") || get(ing, "spec.backend.serviceName");
    if (dflt) names.add(dflt);
    for (const r of arr(get(ing, "spec.rules"))) for (const p of arr(get(r, "http.paths"))) { const n = get(p, "backend.service.name") || get(p, "backend.serviceName"); if (n) names.add(n); }
    for (const n of names) { const k = ing.metadata.namespace + "/" + n; (ingBySvc.get(k) || ingBySvc.set(k, []).get(k)).push(ing); }
  }
  const services = K("Service").map((s) => {
    const sel = get(s, "spec.selector");
    const matched = isObj(sel) && Object.keys(sel).length ? (nsWorkloads.get(s.metadata.namespace) || []).filter((w) => selectorMatches(sel, w.labels)) : [];
    const ings = ingBySvc.get(s.metadata.namespace + "/" + s.metadata.name) || [];
    const type = str(get(s, "spec.type") || "ClusterIP");
    return { obj: s, type, matched, ings, selector: sel, ports: arr(get(s, "spec.ports")).map((p) => (p.nodePort ? p.port + ":" + p.nodePort : str(p.port)) + "/" + str(p.protocol || "TCP")).join(", ") };
  });
  for (const w of workloads) { w.exposure = []; w.expo = "none"; }
  for (const s of services) for (const w of s.matched) {
    const via = [s.type + " svc/" + s.obj.metadata.name, ...s.ings.map((i) => "Ingress ing/" + i.metadata.name)];
    w.exposure.push(...via);
    for (const t of [s.type, ...(s.ings.length ? ["Ingress"] : [])]) if ((EXPO_RANK[t] || 0) > EXPO_RANK[w.expo]) w.expo = t;
  }
  for (const w of workloads) w.exposure = uniq(w.exposure);

  // NetworkPolicy coverage.
  const nsPolicies = new Map();
  for (const p of K("NetworkPolicy")) (nsPolicies.get(p.metadata.namespace) || nsPolicies.set(p.metadata.namespace, []).get(p.metadata.namespace)).push(p);
  for (const w of workloads) {
    const pols = nsPolicies.get(w.namespace) || [];
    w.covered = pols.some((p) => emptySelector(get(p, "spec.podSelector")) || selectorMatches(get(p, "spec.podSelector"), w.labels));
    w.coverage = !has("NetworkPolicy") ? "unknown" : w.covered ? "covered" : pols.length ? "not selected" : "no policy in namespace";
  }

  // Per-workload facts.
  const saRbac = (w) => graph.subjects.get("ServiceAccount:" + w.namespace + ":" + w.sa);
  workloads.forEach((w, i) => {
    if (i % 1000 === 0) progress(i, workloads.length, "workload posture");
    w.facts = w.containers.map((x) => ({ ...x, f: containerFacts(w, x.c), name: str(x.c.name) }));
    w.privileged = w.facts.some((x) => x.f.privileged);
    w.hostNs = ["hostNetwork", "hostPID", "hostIPC"].filter((k) => w.spec[k] === true);
    w.root = w.facts.some((x) => x.f.root === "uid0") ? "uid0" : w.facts.some((x) => x.f.root === "possible") ? "possible" : "no";
    w.hostPaths = arr(w.spec.volumes).filter((v) => v && v.hostPath).map((v) => ({ name: v.name, path: str(v.hostPath.path), sensitive: SENSITIVE_HOSTPATH.some((re) => re.test(str(v.hostPath.path).replace(/\/+$/, "") || "/")) }));
    const sub = saRbac(w);
    w.saPerms = sub ? Array.from(sub.perms.keys()).sort() : [];
    w.saClusterAdmin = !!(sub && sub.clusterAdmin);
  });
  const wAsset = (w) => ({ type: "ASSET", name: cluster + "/" + w.ref, data: { kind: "k8s-workload", namespace: w.namespace, images: w.images, exposure: w.exposure.length ? w.exposure : ["none"] } });
  const external = (w) => w.expo === "LoadBalancer" || w.expo === "Ingress";

  const add = (check, f) => {
    const d = DET[check];
    const ev = arr(f.evidence);
    findings.push({
      id: check + ":" + str(f.key),
      check, title: f.title, severity: f.severity, confidence: f.confidence || "confirmed", category: d.category,
      description: f.description, recommendation: f.recommendation, controls: f.controls || d.controls,
      evidence: ev.slice(0, 50), evidenceCount: ev.length,
      assets: [...arr(f.assets).slice(0, 50), clusterAsset],
      namespaces: uniq(arr(f.namespaces)), path: str(f.path), yaml: str(f.yaml), tags: uniq(arr(f.tags)),
    });
  };
  /** Aggregate rows across workloads into one finding. rows: [{w, ...evidence}] */
  const aggregate = (check, rows, base) => {
    if (!rows.length) return;
    const ws = new Map();
    for (const r of rows) if (r.w) ws.set(r.w.ref, r.w);
    const first = rows[0];
    add(check, {
      key: "all", ...base,
      evidence: rows.map(({ w, yaml, ...r }) => (w ? { namespace: w.namespace, kind: w.kind, name: w.name, ...r } : r)),
      assets: Array.from(ws.values()).map(wAsset), namespaces: Array.from(ws.values()).map((w) => w.namespace).concat(rows.map((r) => r.namespace).filter(Boolean)),
      path: base.path || (first.w ? first.w.ref + " " + (first.path || first.w.base) : str(first.path)), yaml: base.yaml || str(first.yaml),
    });
  };
  const remediation = { namespaces: new Map(), workloads: new Map() };
  const patch = (w, cname, key, val) => {
    const m = remediation.workloads.get(w.ref) || remediation.workloads.set(w.ref, { ref: w.ref, base: w.base, containers: new Map() }).get(w.ref);
    const c = m.containers.get(cname) || m.containers.set(cname, {}).get(cname);
    c[key] = val;
  };

  // ---- RBAC ----------------------------------------------------------------
  const anyBindings = gate("rbac.cluster_admin");
  if (anyBindings) {
    for (const b of graph.bindings) {
      if (!b.clusterAdmin) continue;
      const bo = b.binding;
      for (const s of b.subjects) {
        if (!s || !s.name) continue;
        if (bo.kind === "ClusterRoleBinding" && bo.metadata.name === "cluster-admin" && s.kind === "Group" && s.name === "system:masters") continue; // built-in default
        const bref = bo.kind + "/" + (bo.metadata.namespace ? bo.metadata.namespace + "/" : "") + bo.metadata.name;
        let sev, conf = "confirmed", why;
        if (bo.kind === "RoleBinding") { sev = isBroad(s) ? "high" : "medium"; why = (isBroad(s) ? "every member of " + s.name + " gets " : "") + "full control of namespace " + bo.metadata.namespace + ", including its secrets"; }
        else if (isBroad(s)) { sev = o.authenticatedCritical ? "critical" : "high"; why = "every " + (s.name === "system:serviceaccounts" ? "service account" : s.name === "system:authenticated" ? "authenticated identity" : "anonymous request") + " is a cluster administrator"; }
        else if (s.kind === "ServiceAccount" && SYSTEM_NS.includes(s.namespace || bo.metadata.namespace)) { sev = "medium"; conf = "review"; why = "a kube-system service account is cluster-admin (common for add-ons, but any pod using it owns the cluster)"; }
        else { sev = "high"; why = s.kind === "ServiceAccount" ? "any pod running as this service account owns the cluster" : "this " + s.kind.toLowerCase() + " has unrestricted cluster access"; }
        const assets = [];
        if (s.kind === "User" || s.kind === "Group") assets.push({ type: "IDENTITY", name: s.name, data: { kind: "k8s-" + s.kind.toLowerCase(), clusterAdmin: bo.kind === "ClusterRoleBinding", cluster } });
        add("rbac.cluster_admin", {
          key: bref + ":" + subjectKey(s, bo.metadata.namespace),
          title: "cluster-admin bound to " + s.kind + " " + (s.namespace ? s.namespace + "/" : "") + s.name + (bo.kind === "RoleBinding" ? " in namespace " + bo.metadata.namespace : ""),
          severity: sev, confidence: conf,
          description: bref + " grants the cluster-admin ClusterRole to " + s.kind + " " + s.name + ": " + why + ".",
          recommendation: "Replace the binding with a least-privilege Role scoped to the namespaces and verbs actually needed (CIS 5.1.1); keep cluster-admin for break-glass identities only.",
          evidence: [{ binding: bref, subjectKind: s.kind, subject: s.name, subjectNamespace: str(s.namespace), roleRef: "ClusterRole/cluster-admin", scope: b.scope }],
          assets, namespaces: bo.metadata.namespace ? [bo.metadata.namespace] : [], path: bref + " subjects", yaml: snippet({ roleRef: bo.roleRef, subjects: bo.subjects }),
          tags: isBroad(s) ? ["broad-group"] : [],
        });
      }
      // Dangerous (non cluster-admin) permissions handed to every authenticated / anonymous identity.
    }
    for (const b of graph.bindings) {
      if (b.clusterAdmin || !b.perms.length) continue;
      const broad = b.subjects.filter((s) => s && isBroad(s));
      if (!broad.length) continue;
      const bo = b.binding, bref = bo.kind + "/" + (bo.metadata.namespace ? bo.metadata.namespace + "/" : "") + bo.metadata.name;
      add("rbac.dangerous_role", {
        key: "broad:" + bref,
        title: "Dangerous permissions granted to " + broad.map((s) => s.name).join(", "),
        severity: b.perms.some((p) => p.sev === "high") ? (o.authenticatedCritical ? "critical" : "high") : "high",
        description: bref + " binds " + b.role.kind + "/" + b.role.name + " (" + b.perms.map((p) => p.label).join(", ") + ") to " + broad.map((s) => s.name).join(", ") + (b.scope === "cluster" ? " cluster-wide." : " in namespace " + b.scope + "."),
        recommendation: "Remove broad groups from the binding and grant the role to named users, groups or service accounts.",
        evidence: broad.map((s) => ({ binding: bref, subject: s.name, role: b.role.kind + "/" + b.role.name, permissions: b.perms.map((p) => p.label).join("; ") })),
        namespaces: bo.metadata.namespace ? [bo.metadata.namespace] : [], path: bref, yaml: snippet({ roleRef: bo.roleRef, subjects: bo.subjects }), tags: ["broad-group"],
      });
    }
  }

  const boundTo = new Map();
  for (const b of graph.bindings) { const k = b.role.key; (boundTo.get(k) || boundTo.set(k, []).get(k)).push(b); }
  const roleList = Array.from(roles.values()).sort((a, b) => cmp(a.key, b.key));
  if (gate("rbac.wildcard")) {
    for (const r of roleList) {
      if (isBuiltinRole(r.name)) continue;
      const wild = r.own.filter(hasWildcard);
      if (!wild.length) continue;
      const full = wild.some((x) => arr(x.verbs).includes("*") && arr(x.resources).includes("*"));
      const bound = boundTo.get(r.key) || [];
      add("rbac.wildcard", {
        key: r.key, title: r.kind + " " + (r.namespace ? r.namespace + "/" : "") + r.name + " uses wildcards in rules",
        severity: !bound.length ? "low" : full ? "high" : "medium", confidence: bound.length ? "confirmed" : "review",
        description: wild.length + " rule(s) use \"*\" for verbs, resources or apiGroups, which also grants any resource or verb added to the API later." + (bound.length ? " Bound by " + bound.length + " binding(s)." : " Not bound by any binding in the dump."),
        recommendation: "Replace wildcards with the explicit apiGroups, resources and verbs the workload needs (CIS 5.1.3).",
        evidence: wild.map((x) => ({ role: r.key, apiGroups: arr(x.apiGroups).join(","), resources: arr(x.resources).join(","), verbs: arr(x.verbs).join(","), boundBy: bound.map((b) => b.binding.metadata.name).join(", ") })),
        namespaces: r.namespace ? [r.namespace] : [], path: r.key + " rules", yaml: snippet({ rules: wild }),
      });
    }
  }
  if (gate("rbac.dangerous_role")) {
    for (const r of roleList) {
      if (isBuiltinRole(r.name)) continue;
      const perms = dangerousPerms(r.rules).filter((p) => p.key !== "wildcard");
      if (!perms.length || r.rules.some((x) => arr(x.verbs).includes("*") && arr(x.resources).includes("*") && arr(x.apiGroups).includes("*"))) continue;
      const bound = boundTo.get(r.key) || [];
      const subs = uniq(bound.flatMap((b) => b.subjects.filter(Boolean).map((s) => s.kind + " " + (s.kind === "ServiceAccount" ? str(s.namespace || b.binding.metadata.namespace) + "/" : "") + s.name)));
      const worst = perms.reduce((a, p) => sevMax(a, p.sev), "low");
      add("rbac.dangerous_role", {
        key: r.key, title: r.kind + " " + (r.namespace ? r.namespace + "/" : "") + r.name + " grants " + perms.map((p) => p.label).join(", "),
        severity: bound.length ? worst : "low", confidence: bound.length ? "confirmed" : "review",
        description: "Effective rules" + (r.aggregatedFrom.length ? " (aggregated from " + r.aggregatedFrom.join(", ") + ")" : "") + " allow: " + perms.map((p) => p.label + (p.scoped ? " (named resources only)" : "")).join("; ") + ". " + (subs.length ? "Bound to: " + subs.join("; ") + "." : "Not bound by any binding in the dump."),
        recommendation: "Remove pod creation, exec, secret read, impersonate, bind and escalate rights unless the subject strictly needs them (CIS 5.1.2, 5.1.4, 5.1.8); scope with resourceNames where possible.",
        evidence: perms.map((p) => ({ role: r.key, permission: p.label, scopedByName: p.scoped ? "yes" : "no", boundTo: subs.join("; ") })),
        namespaces: r.namespace ? [r.namespace] : [], path: r.key + " rules", yaml: snippet({ rules: r.own, ...(r.obj.aggregationRule ? { aggregationRule: r.obj.aggregationRule } : {}) }),
      });
    }
  }
  if (gate("rbac.orphan_binding")) {
    const rows = [];
    const nsKnown = new Set(objects.map((x) => str(x.metadata.namespace)).concat(K("Namespace").map((n) => n.metadata.name)));
    const saSet = new Set(K("ServiceAccount").map((s) => s.metadata.namespace + "/" + s.metadata.name));
    const roleKinds = K("Role").length + K("ClusterRole").length > 0 || o.assumeComplete;
    for (const b of graph.bindings) {
      const bo = b.binding, bref = bo.kind + "/" + (bo.metadata.namespace ? bo.metadata.namespace + "/" : "") + bo.metadata.name;
      if (roleKinds && !b.role.found && !b.role.builtin) rows.push({ binding: bref, issue: "roleRef " + b.role.kind + "/" + b.role.name + " does not exist", path: bref + " roleRef", namespace: bo.metadata.namespace });
      if (has("ServiceAccount")) for (const s of b.subjects) {
        if (!s || s.kind !== "ServiceAccount") continue;
        const ns = str(s.namespace || bo.metadata.namespace);
        if (nsKnown.has(ns) && !saSet.has(ns + "/" + s.name)) rows.push({ binding: bref, issue: "subject ServiceAccount " + ns + "/" + s.name + " does not exist", path: bref + " subjects", namespace: ns });
      }
    }
    aggregate("rbac.orphan_binding", rows, { title: "Bindings that reference missing roles or service accounts", severity: "low", confidence: "likely",
      description: rows.length + " binding reference(s) point at objects that are not in the dump. A later object created with that name silently inherits the permissions.",
      recommendation: "Delete stale bindings or recreate the intended object deliberately." });
  }
  if (gate("rbac.default_sa_bound")) {
    const rows = [];
    for (const b of graph.bindings) for (const s of b.subjects) {
      if (!s || s.kind !== "ServiceAccount" || s.name !== "default" || isBuiltinRole(b.role.name)) continue;
      const ns = str(s.namespace || b.binding.metadata.namespace);
      if (SYSTEM_NS.includes(ns)) continue;
      rows.push({ namespace: ns, binding: b.binding.kind + "/" + (b.binding.metadata.namespace ? b.binding.metadata.namespace + "/" : "") + b.binding.metadata.name, role: b.role.kind + "/" + b.role.name, permissions: b.perms.map((p) => p.label).join("; ") });
    }
    aggregate("rbac.default_sa_bound", rows, { title: "Roles bound to the default service account", severity: rows.some((r) => r.permissions) ? "high" : "medium",
      description: "Every pod that does not name a service account runs as default, so these rights spread to all of them.",
      recommendation: "Create a dedicated service account per workload and bind roles to it instead of default (CIS 5.1.5)." });
  }
  if (gate("rbac.default_sa_automount")) {
    const rows = K("ServiceAccount").filter((s) => s.metadata.name === "default" && !SYSTEM_NS.includes(s.metadata.namespace) && s.automountServiceAccountToken !== false)
      .map((s) => ({ namespace: s.metadata.namespace, serviceAccount: "default", automountServiceAccountToken: s.automountServiceAccountToken === true ? "true" : "unset (true)", path: s.metadata.namespace + "/ServiceAccount/default" }));
    aggregate("rbac.default_sa_automount", rows, { title: "Default service accounts auto-mount API tokens", severity: "low",
      description: rows.length + " namespace(s) let every pod using the default service account receive an API token.",
      recommendation: "Set automountServiceAccountToken: false on each namespace's default ServiceAccount (CIS 5.1.5).", yaml: "automountServiceAccountToken: false" });
  }
  if (anyBindings && gate("rbac.automount_unneeded")) {
    const saObj = new Map(K("ServiceAccount").map((s) => [s.metadata.namespace + "/" + s.metadata.name, s]));
    const rows = [];
    for (const w of workloads) {
      if (SYSTEM_NS.includes(w.namespace) || w.spec.automountServiceAccountToken === false) continue;
      const sa = saObj.get(w.namespace + "/" + w.sa);
      if (sa && sa.automountServiceAccountToken === false) continue;
      if (saRbac(w)) continue;
      rows.push({ w, serviceAccount: w.sa, reason: "service account has no RoleBinding / ClusterRoleBinding but a token is mounted", path: w.base + ".automountServiceAccountToken" });
    }
    aggregate("rbac.automount_unneeded", rows, { title: "Workloads mount an API token they have no RBAC use for", severity: "low", confidence: "likely",
      description: rows.length + " workload(s) run as a service account with no bindings in the dump, yet still receive a token a compromised container could use against the API server (T1552.007).",
      recommendation: "Set automountServiceAccountToken: false on the pod spec or the service account (CIS 5.1.6).", yaml: "automountServiceAccountToken: false" });
  }

  // ---- Pod security ------------------------------------------------------------
  const podGate = gate("pod.privileged");
  if (podGate) {
    for (const k of ["pod.host_namespaces", "pod.privilege_escalation", "pod.run_as_root", "pod.net_raw", "pod.added_capabilities", "pod.hostpath", "pod.hostport", "pod.windows_hostprocess", "pod.no_limits", "pod.image_tag", "pod.image_registry", "pod.secret_env", "pod.literal_secret_env", "pod.no_seccomp", "pod.writable_rootfs", "pod.shared_process_ns", "pod.sysctls", "cluster.default_namespace", "cluster.system_unknown_image"]) gate(k);
    const A = {};
    const row = (k, r) => (A[k] || (A[k] = [])).push(r);
    const sysTitle = (w) => (w.system ? " (expected for system component)" : "");
    const sysSev = (w, s) => (w.system ? "info" : s);
    workloads.forEach((w, i) => {
      if (i % 1000 === 0) progress(i, workloads.length, "pod security");
      const wx = [wAsset(w)];
      const priv = w.facts.filter((x) => x.f.privileged);
      if (priv.length) {
        add("pod.privileged", { key: w.ref, title: "Privileged container in " + w.ref + sysTitle(w), severity: sysSev(w, external(w) ? "critical" : "high"),
          description: priv.map((x) => x.name).join(", ") + " run with privileged: true, which gives root on the node (all capabilities, all devices). " + (external(w) ? "The workload is reachable from outside the cluster via " + w.exposure.join(", ") + "." : ""),
          recommendation: "Remove privileged: true; grant only the specific capabilities needed and enforce the baseline Pod Security Standard on the namespace (CIS 5.2.2).",
          evidence: priv.map((x) => ({ container: x.name, path: x.path + ".securityContext.privileged", image: str(x.c.image) })), assets: wx, namespaces: [w.namespace],
          path: w.ref + " " + priv[0].path + ".securityContext", yaml: snippet({ securityContext: priv[0].c.securityContext }), tags: w.system ? ["expected-system"] : [] });
        if (!w.system) for (const x of priv) patch(w, x.name, "privileged", false);
      }
      if (w.hostNs.length) {
        add("pod.host_namespaces", { key: w.ref, title: "Host namespaces shared by " + w.ref + " (" + w.hostNs.join(", ") + ")" + sysTitle(w),
          severity: sysSev(w, w.hostNs.some((k) => k !== "hostNetwork") ? "high" : "medium"),
          description: w.hostNs.join(", ") + " lets the pod see host processes, IPC or the node network stack, defeating container isolation.",
          recommendation: "Remove " + w.hostNs.join(", ") + " (CIS 5.2.3 to 5.2.5) unless this is a node agent that needs it.",
          evidence: w.hostNs.map((k) => ({ field: k, path: w.base + "." + k, value: true })), assets: wx, namespaces: [w.namespace], path: w.ref + " " + w.base, yaml: snippet(Object.fromEntries(w.hostNs.map((k) => [k, true]))), tags: w.system ? ["expected-system"] : [] });
      }
      if (w.hostPaths.length) {
        const sens = w.hostPaths.filter((h) => h.sensitive);
        const sock = w.hostPaths.some((h) => /docker\.sock|containerd|crio/.test(h.path) || h.path === "/");
        add("pod.hostpath", { key: w.ref, title: "hostPath volume" + (w.hostPaths.length > 1 ? "s" : "") + " in " + w.ref + " (" + w.hostPaths.map((h) => h.path).join(", ") + ")" + sysTitle(w),
          severity: sysSev(w, sock ? "critical" : sens.length ? "high" : "medium"),
          description: "The pod mounts host paths" + (sens.length ? "; " + sens.map((h) => h.path).join(", ") + " expose(s) the container runtime, host configuration or kernel interfaces (container escape, T1611)." : "."),
          recommendation: "Replace hostPath with ConfigMap, Secret, emptyDir or a PersistentVolumeClaim; if a host mount is unavoidable, make it readOnly and as narrow as possible.",
          evidence: w.hostPaths.map((h) => ({ volume: h.name, hostPath: h.path, sensitive: h.sensitive ? "yes" : "no" })), assets: wx, namespaces: [w.namespace],
          path: w.ref + " " + w.base + ".volumes", yaml: snippet({ volumes: arr(w.spec.volumes).filter((v) => v && v.hostPath) }), tags: w.system ? ["expected-system"] : [] });
      }
      const hp = w.facts.filter((x) => x.f.hostProcess);
      if (hp.length) add("pod.windows_hostprocess", { key: w.ref, title: "Windows HostProcess container in " + w.ref, severity: sysSev(w, "high"),
        description: "HostProcess containers run directly on the Windows node with host privileges.", recommendation: "Disallow windowsOptions.hostProcess outside node-agent namespaces (baseline Pod Security Standard).",
        evidence: hp.map((x) => ({ container: x.name, path: x.path + ".securityContext.windowsOptions.hostProcess" })), assets: wx, namespaces: [w.namespace], path: w.ref + " " + hp[0].path, yaml: snippet({ securityContext: hp[0].c.securityContext || w.spec.securityContext }) });
      const caps = w.facts.filter((x) => x.f.added.some((c) => DANGEROUS_CAPS.includes(c)));
      if (caps.length) add("pod.added_capabilities", { key: w.ref, title: "Dangerous capabilities added in " + w.ref + sysTitle(w), severity: sysSev(w, "high"),
        description: caps.map((x) => x.name + ": " + x.f.added.join(", ")).join("; ") + ". These capabilities allow kernel, network or process manipulation that can lead to container escape.",
        recommendation: "Drop ALL capabilities and add back only what is required (CIS 5.2.9); NET_BIND_SERVICE is the only addition the restricted profile allows.",
        evidence: caps.map((x) => ({ container: x.name, added: x.f.added.join(", "), path: x.path + ".securityContext.capabilities.add" })), assets: wx, namespaces: [w.namespace], path: w.ref + " " + caps[0].path + ".securityContext.capabilities", yaml: snippet({ capabilities: get(caps[0].c, "securityContext.capabilities") }) });
      for (const x of w.facts) {
        const lit = literalSecretEnv(x.c);
        if (lit.length) row("pod.literal_secret_env", { w, container: x.name, variables: lit.map((l) => l.name + "=" + l.masked).join(", "), path: x.path + ".env", yaml: snippet({ env: arr(x.c.env).filter((e) => lit.some((l) => l.name === e.name)) }) });
        const sref = arr(x.c.env).filter((e) => get(e, "valueFrom.secretKeyRef")).map((e) => e.name).concat(arr(x.c.envFrom).filter((e) => e.secretRef).map((e) => "envFrom:" + e.secretRef.name));
        if (sref.length) row("pod.secret_env", { w, container: x.name, variables: sref.join(", "), path: x.path + ".env" });
        if (w.system) continue;
        if (!x.f.privileged && x.f.allowPrivEsc) { row("pod.privilege_escalation", { w, container: x.name, path: x.path + ".securityContext.allowPrivilegeEscalation", value: "unset (true)" }); patch(w, x.name, "allowPrivilegeEscalation", false); }
        if (x.f.root !== "no") { row("pod.run_as_root", { w, container: x.name, runAs: x.f.root === "uid0" ? "runAsUser: 0" : "no runAsNonRoot / runAsUser", path: x.path + ".securityContext" }); patch(w, x.name, "runAsNonRoot", true); }
        if (!x.f.netRawDropped && !x.f.privileged) { row("pod.net_raw", { w, container: x.name, path: x.path + ".securityContext.capabilities.drop" }); patch(w, x.name, "capabilities", { drop: ["ALL"] }); }
        const nonDanger = x.f.added.filter((c) => !DANGEROUS_CAPS.includes(c));
        if (nonDanger.length) row("pod.added_capabilities", { w, container: x.name, added: nonDanger.join(", "), path: x.path + ".securityContext.capabilities.add" });
        if (x.f.hostPorts.length && w.spec.hostNetwork !== true) row("pod.hostport", { w, container: x.name, hostPorts: x.f.hostPorts.join(", "), path: x.path + ".ports" });
        if (x.f.noLimits.length && !x.init) row("pod.no_limits", { w, container: x.name, missing: x.f.noLimits.join(", "), path: x.path + ".resources.limits" });
        if (x.f.seccomp !== "RuntimeDefault" && x.f.seccomp !== "Localhost") { row("pod.no_seccomp", { w, container: x.name, seccompProfile: x.f.seccomp || "unset", path: x.path + ".securityContext.seccompProfile" }); patch(w, x.name, "seccompProfile", { type: "RuntimeDefault" }); }
        if (!x.f.readOnlyRoot) { row("pod.writable_rootfs", { w, container: x.name, path: x.path + ".securityContext.readOnlyRootFilesystem" }); patch(w, x.name, "readOnlyRootFilesystem", true); }
        if (!x.f.probes && !x.init && ["Deployment", "StatefulSet", "DaemonSet"].includes(w.kind)) row("pod.no_probes", { w, container: x.name, path: x.path });
      }
      if (!w.system) {
        if (w.spec.shareProcessNamespace === true) row("pod.shared_process_ns", { w, path: w.base + ".shareProcessNamespace" });
        const sys = arr(get(w.spec, "securityContext.sysctls")).filter((s) => s && !SAFE_SYSCTLS.includes(s.name));
        if (sys.length) row("pod.sysctls", { w, sysctls: sys.map((s) => s.name + "=" + str(s.value)).join(", "), path: w.base + ".securityContext.sysctls" });
        if (w.namespace === "default") row("cluster.default_namespace", { w, path: w.ref });
      }
      for (const img of w.images) {
        const p = parseImage(img);
        if (!w.system && p.floating) row("pod.image_tag", { w, image: img, tag: p.tag || "(none)", path: w.base + ".containers[].image" });
        if (allowed.length && !allowed.some((a) => (p.registry + "/" + p.repository).startsWith(a) || p.registry === a)) row("pod.image_registry", { w, image: img, registry: p.registry, path: w.base + ".containers[].image" });
        if (w.namespace === "kube-system" && !w.system && !KNOWN_SYSTEM_REGISTRIES.test(p.registry + "/" + p.repository)) row("cluster.system_unknown_image", { w, image: img, registry: p.registry });
      }
    });
    const AG = (k, base) => aggregate(k, A[k] || [], base);
    AG("pod.literal_secret_env", { title: "Credential-like values written literally into container env", severity: "high", confidence: "likely",
      description: "Environment variables named like passwords, tokens or keys carry literal values in the pod spec, readable by anyone who can get the workload object. Values are masked here.",
      recommendation: "Move the values into Secrets (or an external secret store) and reference them with secretKeyRef; rotate the exposed credentials (CIS 5.4.1)." });
    AG("pod.secret_env", { title: "Secrets exposed as environment variables", severity: "info",
      description: "Secrets passed through env are visible in /proc, crash dumps and child processes.", recommendation: "Prefer mounting secrets as files (CIS 5.4.1)." });
    AG("pod.privilege_escalation", { title: "Containers allow privilege escalation", severity: "medium",
      description: "allowPrivilegeEscalation is not set to false, so setuid binaries can gain more privileges than the parent process.", recommendation: "Set allowPrivilegeEscalation: false in every container securityContext (CIS 5.2.6).", yaml: "securityContext:\n  allowPrivilegeEscalation: false" });
    const rootRows = A["pod.run_as_root"] || [];
    AG("pod.run_as_root", { title: "Containers may run as root", severity: rootRows.some((r) => r.runAs === "runAsUser: 0") ? "high" : "medium", confidence: rootRows.some((r) => r.runAs === "runAsUser: 0") ? "confirmed" : "likely",
      description: "runAsNonRoot is not true and no non-zero runAsUser is set; the image default user (often root) applies.", recommendation: "Set runAsNonRoot: true and a non-zero runAsUser (CIS 5.2.7).", yaml: "securityContext:\n  runAsNonRoot: true\n  runAsUser: 10001" });
    AG("pod.net_raw", { title: "NET_RAW capability not dropped", severity: "low",
      description: "NET_RAW allows raw sockets (ARP / DNS spoofing inside the node network).", recommendation: "Drop ALL capabilities (CIS 5.2.8).", yaml: "securityContext:\n  capabilities:\n    drop: [\"ALL\"]" });
    AG("pod.added_capabilities", { title: "Containers add Linux capabilities", severity: "medium",
      description: "Capabilities beyond the runtime default are added.", recommendation: "Remove added capabilities unless justified (CIS 5.2.9)." });
    AG("pod.hostport", { title: "Containers bind host ports", severity: "medium",
      description: "hostPort exposes the container on every node IP, bypassing Service and NetworkPolicy controls.", recommendation: "Use a Service (NodePort / LoadBalancer) instead of hostPort (CIS 5.2.13)." });
    AG("pod.no_limits", { title: "Containers without CPU / memory limits", severity: "low",
      description: "Without limits one container can exhaust node resources (denial of service).", recommendation: "Set resources.limits for cpu and memory, or a LimitRange per namespace." });
    AG("pod.no_seccomp", { title: "Containers without a seccomp profile", severity: (A["pod.no_seccomp"] || []).some((r) => r.seccompProfile === "Unconfined") ? "medium" : "low",
      description: "No RuntimeDefault or Localhost seccomp profile applies, so the full syscall surface is available.", recommendation: "Set seccompProfile.type: RuntimeDefault at pod level (CIS 5.7.2).", yaml: "securityContext:\n  seccompProfile:\n    type: RuntimeDefault" });
    AG("pod.writable_rootfs", { title: "Containers with a writable root filesystem", severity: "low",
      description: "An attacker can drop tools or modify binaries inside the container.", recommendation: "Set readOnlyRootFilesystem: true and mount emptyDir for paths that must be writable.", yaml: "securityContext:\n  readOnlyRootFilesystem: true" });
    AG("pod.no_probes", { title: "Long-running containers without health probes", severity: "low",
      description: "No liveness, readiness or startup probe: failures go unnoticed and traffic reaches broken pods.", recommendation: "Add readiness and liveness probes." });
    AG("pod.shared_process_ns", { title: "Pods share one process namespace", severity: "medium",
      description: "shareProcessNamespace lets every container see and signal the others' processes and read their /proc environment.", recommendation: "Remove shareProcessNamespace unless a debugging sidecar strictly needs it." });
    AG("pod.sysctls", { title: "Pods set unsafe sysctls", severity: "medium",
      description: "Sysctls outside the safe set change kernel parameters shared with the node.", recommendation: "Use only the safe sysctl set allowed by the baseline Pod Security Standard." });
    AG("pod.image_tag", { title: "Images use :latest or no tag", severity: "medium",
      description: "Floating tags make the running code unknowable and allow a pushed image to change production silently.", recommendation: "Pin images to an immutable version tag and digest (image@sha256:...)." });
    if (allowed.length) AG("pod.image_registry", { title: "Images from registries outside the allow-list", severity: "high", confidence: "confirmed",
      description: "Allowed registries: " + allowed.join(", ") + ".", recommendation: "Pull only from approved registries and enforce it with an admission policy (Kyverno, Gatekeeper or ValidatingAdmissionPolicy)." });
    else {
      const regs = new Map();
      for (const w of workloads) for (const img of w.images) { const r = parseImage(img).registry; (regs.get(r) || regs.set(r, new Set()).get(r)).add(w.ref); }
      if (regs.size) add("pod.image_registry", { key: "inventory", title: "Image registries in use (no allow-list set)", severity: "info", confidence: "review",
        description: regs.size + " registr" + (regs.size === 1 ? "y" : "ies") + " in use. Enter the allowed registries to turn this into a policy check.", recommendation: "Define an approved-registry list and enforce it at admission.",
        evidence: Array.from(regs.keys()).sort().map((r) => ({ registry: r, workloads: regs.get(r).size })) });
    }
    AG("cluster.default_namespace", { title: "Workloads running in the default namespace", severity: "low",
      description: "The default namespace usually lacks dedicated RBAC, quotas and policies.", recommendation: "Move workloads into dedicated namespaces (CIS 5.7.4)." });
    AG("cluster.system_unknown_image", { title: "kube-system workloads from unrecognised images", severity: "medium", confidence: "review",
      description: "kube-system holds the control-plane add-ons; workloads there that are not well-known components and pull from other registries deserve a look (T1610).", recommendation: "Confirm each workload's owner and provenance; move application workloads out of kube-system." });
  }

  // ---- Namespaces / PSA -------------------------------------------------------
  if (gate("ns.psa_labels")) {
    const miss = [], priv = [];
    for (const n of K("Namespace")) {
      if (SYSTEM_NS.includes(n.metadata.name)) continue;
      const enf = str((n.metadata.labels || {})["pod-security.kubernetes.io/enforce"]);
      const count = (nsWorkloads.get(n.metadata.name) || []).length;
      if (!enf) miss.push({ namespace: n.metadata.name, enforce: "(missing)", workloads: count, path: "Namespace/" + n.metadata.name + " metadata.labels" });
      else if (enf === "privileged") priv.push({ namespace: n.metadata.name, enforce: enf, workloads: count, path: "Namespace/" + n.metadata.name + " metadata.labels" });
    }
    aggregate("ns.psa_labels", miss, { title: "Namespaces without a Pod Security Admission enforce label", severity: "medium",
      description: "Without pod-security.kubernetes.io/enforce the namespace accepts privileged pods.", recommendation: "Label each namespace with pod-security.kubernetes.io/enforce: restricted (or baseline where restricted is not yet possible) (CIS 5.2.1).",
      yaml: "metadata:\n  labels:\n    pod-security.kubernetes.io/enforce: restricted\n    pod-security.kubernetes.io/enforce-version: latest" });
    if (priv.length) add("ns.psa_labels", { key: "privileged", title: "Namespaces enforce the privileged Pod Security level", severity: "high",
      description: "enforce: privileged disables Pod Security Admission for these namespaces.", recommendation: "Move to baseline or restricted; isolate genuinely privileged agents in a dedicated namespace.",
      evidence: priv, namespaces: priv.map((r) => r.namespace), path: priv[0].path, yaml: "pod-security.kubernetes.io/enforce: privileged" });
  }
  if (K("PodSecurityPolicy").length) add("ns.legacy_psp", { key: "psp", title: "Legacy PodSecurityPolicy objects present", severity: "low",
    description: K("PodSecurityPolicy").length + " PodSecurityPolicy object(s). PSP was removed in Kubernetes 1.25, so these enforce nothing on current clusters.", recommendation: "Migrate to Pod Security Admission labels or a policy engine, then delete the PSPs.",
    evidence: K("PodSecurityPolicy").map((p) => ({ name: p.metadata.name, privileged: get(p, "spec.privileged") === true ? "yes" : "no" })) });

  // ---- Network ---------------------------------------------------------------
  if (gate("net.no_policy")) {
    gate("net.no_default_deny"); gate("net.policy_selects_nothing");
    const uncovered = [];
    for (const [ns, ws] of Array.from(nsWorkloads.entries()).sort((a, b) => cmp(a[0], b[0]))) {
      if (SYSTEM_NS.includes(ns)) continue;
      const pols = nsPolicies.get(ns) || [];
      const assets = ws.map(wAsset);
      if (!pols.length) {
        add("net.no_policy", { key: ns, title: "Namespace " + ns + " has workloads but no NetworkPolicy", severity: ws.some(external) ? "high" : "medium",
          description: ws.length + " workload(s) accept traffic from any pod in the cluster and can reach any destination (no lateral-movement boundary).",
          recommendation: "Apply a default-deny ingress and egress NetworkPolicy, then allow the required flows explicitly (CIS 5.3.2).",
          evidence: ws.map((w) => ({ namespace: ns, kind: w.kind, name: w.name, exposure: w.expo })), assets, namespaces: [ns], path: "Namespace/" + ns });
        remediation.namespaces.set(ns, { ingress: true, egress: true });
        continue;
      }
      const ingDeny = pols.some((p) => isDefaultDeny(p, "Ingress")), egDeny = pols.some((p) => isDefaultDeny(p, "Egress"));
      if (!ingDeny || !egDeny) {
        add("net.no_default_deny", { key: ns, title: "Namespace " + ns + " has no default-deny " + [!ingDeny && "ingress", !egDeny && "egress"].filter(Boolean).join(" / ") + " policy", severity: !ingDeny ? "low" : "info",
          description: pols.length + " NetworkPolicy object(s) exist, but none selects every pod with an empty rule set, so pods not covered by a policy stay open.",
          recommendation: "Add a policy with podSelector: {} and empty " + [!ingDeny && "ingress", !egDeny && "egress"].filter(Boolean).join(" and ") + " rules.",
          evidence: pols.map((p) => ({ namespace: ns, policy: p.metadata.name, podSelector: JSON.stringify(get(p, "spec.podSelector") || {}), policyTypes: arr(get(p, "spec.policyTypes")).join(",") })), assets, namespaces: [ns], path: ns + "/NetworkPolicy" });
        remediation.namespaces.set(ns, { ingress: !ingDeny, egress: !egDeny });
      }
      for (const w of ws) if (!w.covered) uncovered.push({ w, policies: pols.length });
    }
    aggregate("net.no_policy", uncovered, { key: "uncovered", title: "Workloads not selected by any NetworkPolicy", severity: "low",
      description: "These workloads sit in namespaces that have policies, but no policy selects their pod labels.", recommendation: "Extend a policy's podSelector or add a namespace default-deny." });
    const anyWorkloadKinds = WORKLOAD_KINDS.some((k) => K(k).length);
    if (anyWorkloadKinds) {
      const rows = [];
      for (const p of K("NetworkPolicy")) {
        const sel = get(p, "spec.podSelector");
        if (emptySelector(sel)) continue;
        const ws = nsWorkloads.get(p.metadata.namespace) || [];
        if (!ws.some((w) => selectorMatches(sel, w.labels))) rows.push({ namespace: p.metadata.namespace, policy: p.metadata.name, podSelector: JSON.stringify(sel), path: p.metadata.namespace + "/NetworkPolicy/" + p.metadata.name + " spec.podSelector", yaml: snippet({ podSelector: sel }) });
      }
      aggregate("net.policy_selects_nothing", rows, { title: "NetworkPolicies that select no workload", severity: "low", confidence: "likely",
        description: "The podSelector matches no pod template labels in the namespace: the policy protects nothing (often a label typo).", recommendation: "Fix the selector labels or delete the stale policy." });
    }
  }
  const exposureRows = [];
  if (gate("net.exposed_privileged")) {
    gate("net.service_no_endpoints");
    const noEp = [];
    for (const s of services) {
      const so = s.obj, sref = so.metadata.namespace + "/Service/" + so.metadata.name;
      const ext = s.type === "LoadBalancer" || s.ings.length > 0, np = s.type === "NodePort";
      if (isObj(s.selector) && Object.keys(s.selector).length && !s.matched.length && WORKLOAD_KINDS.some((k) => K(k).length)) noEp.push({ namespace: so.metadata.namespace, service: so.metadata.name, selector: JSON.stringify(s.selector), path: sref + " spec.selector" });
      if (!s.matched.length) exposureRows.push({ namespace: so.metadata.namespace, service: so.metadata.name, type: s.type, ports: s.ports, ingress: s.ings.map((i) => i.metadata.name).join(", "), workload: "", risks: "", severity: "" });
      for (const w of s.matched) {
        const risks = [];
        if (w.privileged) risks.push("privileged");
        if (w.hostNs.length) risks.push(w.hostNs.join("+"));
        if (w.hostPaths.some((h) => h.sensitive)) risks.push("sensitive hostPath");
        if (w.root === "uid0") risks.push("runs as UID 0"); else if (w.root === "possible") risks.push("may run as root");
        if (w.saClusterAdmin) risks.push("service account is cluster-admin");
        else if (w.saPerms.length) risks.push("service account: " + w.saPerms.join("; "));
        const severe = w.privileged || w.hostPaths.some((h) => h.sensitive) || w.saClusterAdmin || w.hostNs.some((k) => k !== "hostNetwork");
        let sev = "";
        if (ext || np) sev = severe ? (ext ? "critical" : "high") : w.root === "uid0" || w.saPerms.length ? (ext ? "high" : "medium") : w.root === "possible" ? (ext ? "medium" : "low") : "";
        if (w.system && sev) sev = "info";
        exposureRows.push({ namespace: so.metadata.namespace, service: so.metadata.name, type: s.type, ports: s.ports, ingress: s.ings.map((i) => i.metadata.name).join(", "), workload: w.kind + "/" + w.name, risks: risks.join("; "), severity: sev });
        if (sev && sev !== "info" && SEV_RANK[sev] >= SEV_RANK.medium) {
          const path = (ext ? (s.ings.length ? "Ingress " + s.ings.map((i) => i.metadata.name).join(", ") + " -> " : "") + s.type : s.type) + " svc/" + so.metadata.name + " -> " + w.ref;
          add("net.exposed_privileged", { key: sref + ">" + w.ref, title: "Externally reachable risky workload: " + path, severity: sev,
            description: "Exposure chain: " + path + ". Workload risk: " + risks.join("; ") + ". A remote compromise of this service lands in a container that can reach the node or the API server.",
            recommendation: "Fix the workload first (drop privileged / host access, run as non-root, least-privilege service account); restrict the Service with loadBalancerSourceRanges or an internal load balancer.",
            evidence: [{ service: sref, type: s.type, ports: s.ports, ingress: s.ings.map((i) => i.metadata.name).join(", "), workload: w.ref, risks: risks.join("; ") }],
            assets: [wAsset(w)], namespaces: [w.namespace], path: sref, yaml: snippet({ spec: { type: s.type, selector: s.selector, ports: get(so, "spec.ports") } }), tags: ["exposure-chain"] });
        }
      }
    }
    aggregate("net.service_no_endpoints", noEp, { title: "Services whose selector matches no workload", severity: "low", confidence: "likely",
      description: "No pod template carries the selector labels, so the Service has no endpoints (stale object, or a typo that will route traffic to whatever later matches).", recommendation: "Delete stale Services or fix the selector." });
  }
  if (gate("net.ingress_no_tls")) {
    gate("net.ingress_ssl_redirect_off");
    for (const ing of K("Ingress")) {
      const iref = ing.metadata.namespace + "/Ingress/" + ing.metadata.name;
      const hosts = uniq(arr(get(ing, "spec.rules")).map((r) => str(r.host)).filter(Boolean));
      if (!arr(get(ing, "spec.tls")).length) add("net.ingress_no_tls", { key: iref, title: "Ingress " + iref + " serves without TLS", severity: "medium",
        description: "No spec.tls section: traffic to " + (hosts.join(", ") || "the default host") + " is plain HTTP unless TLS ends in front of the controller.", recommendation: "Add a tls section with a certificate (for example via cert-manager).",
        evidence: [{ ingress: iref, hosts: hosts.join(", ") }], namespaces: [ing.metadata.namespace], path: iref + " spec.tls", yaml: snippet({ rules: get(ing, "spec.rules") }) });
      const ann = ing.metadata.annotations || {};
      const off = ["nginx.ingress.kubernetes.io/ssl-redirect", "nginx.ingress.kubernetes.io/force-ssl-redirect"].filter((k) => str(ann[k]).toLowerCase() === "false");
      if (off.length && arr(get(ing, "spec.tls")).length) add("net.ingress_ssl_redirect_off", { key: iref, title: "Ingress " + iref + " disables the HTTPS redirect", severity: "medium",
        description: off.join(", ") + " is \"false\", so clients can keep using plain HTTP.", recommendation: "Remove the annotation or set it to \"true\".",
        evidence: off.map((k) => ({ ingress: iref, annotation: k, value: ann[k] })), namespaces: [ing.metadata.namespace], path: iref + " metadata.annotations", yaml: snippet({ annotations: Object.fromEntries(off.map((k) => [k, ann[k]])) }) });
    }
  }

  // ---- Secrets / ConfigMaps ----------------------------------------------------
  if (gate("secret.opaque_default_ns")) {
    for (const k of ["secret.shared", "secret.sa_token", "secret.dockerconfig_spread"]) gate(k);
    const sec = K("Secret");
    aggregate("secret.opaque_default_ns", sec.filter((s) => s.metadata.namespace === "default" && (!s.type || s.type === "Opaque") && SECRET_NAME.test(s.metadata.name)).map((s) => ({ namespace: "default", secret: s.metadata.name, keys: arr(s.dataKeys).join(", ") })),
      { title: "Credential secrets stored in the default namespace", severity: "info", description: "Opaque secrets named like credentials live in default, which is usually readable by broad roles.", recommendation: "Keep secrets in the namespace of the workload that uses them (CIS 5.7.4)." });
    const users = new Map();
    for (const w of workloads) for (const n of secretRefs(w)) { const k = w.namespace + "/" + n; (users.get(k) || users.set(k, []).get(k)).push(w); }
    const shared = Array.from(users.entries()).filter(([, ws]) => ws.length >= o.sharedSecretWorkloads).sort((a, b) => cmp(a[0], b[0]));
    if (shared.length) add("secret.shared", { key: "all", title: "Secrets shared by " + o.sharedSecretWorkloads + "+ workloads", severity: "low", confidence: "review",
      description: "A compromise of any one workload exposes the secret for all of them.", recommendation: "Issue a separate credential per workload so access can be revoked individually.",
      evidence: shared.map(([k, ws]) => ({ secret: k, workloads: ws.length, users: ws.map((w) => w.kind + "/" + w.name).join(", ") })), assets: shared.flatMap(([, ws]) => ws).map(wAsset), namespaces: shared.map(([k]) => k.split("/")[0]) });
    aggregate("secret.sa_token", sec.filter((s) => s.type === "kubernetes.io/service-account-token").map((s) => ({ namespace: s.metadata.namespace, secret: s.metadata.name, serviceAccount: str((s.metadata.annotations || {})["kubernetes.io/service-account.name"]) })),
      { title: "Long-lived service account token secrets", severity: "medium", description: "kubernetes.io/service-account-token secrets never expire; anyone who reads them holds the account's rights indefinitely (T1552.007).", recommendation: "Delete them and use projected, time-bound tokens (TokenRequest API)." });
    const dc = new Map();
    for (const s of sec) if (s.type === "kubernetes.io/dockerconfigjson" || s.type === "kubernetes.io/dockercfg") (dc.get(s.metadata.name) || dc.set(s.metadata.name, []).get(s.metadata.name)).push(s.metadata.namespace);
    aggregate("secret.dockerconfig_spread", Array.from(dc.entries()).filter(([, ns]) => ns.length >= 3).sort((a, b) => cmp(a[0], b[0])).map(([n, ns]) => ({ secret: n, namespaces: ns.sort().join(", "), count: ns.length })),
      { title: "Registry pull credentials copied into many namespaces", severity: "low", description: "The same image-pull secret is replicated across namespaces, widening who can read registry credentials.", recommendation: "Use node-level or workload-identity registry auth, or scope one pull secret per namespace with a read-only token." });
  }
  if (gate("configmap.credential_keys")) {
    const rows = [];
    for (const c of K("ConfigMap")) {
      if (c.metadata.name === "kube-root-ca.crt") continue;
      const keys = arr(c.dataKeys).filter((k) => CRED_KEY.test(k) && !/\.(crt|pem|pub)$/i.test(k));
      if (keys.length) rows.push({ namespace: c.metadata.namespace, configMap: c.metadata.name, keys: keys.join(", "), path: c.metadata.namespace + "/ConfigMap/" + c.metadata.name + " data" });
    }
    aggregate("configmap.credential_keys", rows, { title: "ConfigMap keys named like credentials", severity: "medium", confidence: "review",
      description: "ConfigMaps are not access-controlled like Secrets. These keys are named like credentials (judged by key name only; values were not read).", recommendation: "Move credentials into Secrets (with encryption at rest) and grant read access narrowly." });
  }

  // ---- Cluster -------------------------------------------------------------------
  if (gate("cluster.node_health")) {
    gate("cluster.kubelet_skew");
    aggregate("cluster.node_health", K("Node").map((n) => {
      const ready = arr(get(n, "status.conditions")).find((c) => c.type === "Ready");
      const st = [get(n, "spec.unschedulable") ? "unschedulable" : "", ready && ready.status !== "True" ? "NotReady (" + str(ready.reason) + ")" : ""].filter(Boolean);
      return st.length ? { node: n.metadata.name, status: st.join(", "), kubelet: str(get(n, "status.nodeInfo.kubeletVersion")) } : null;
    }).filter(Boolean), { title: "Nodes unschedulable or not ready", severity: "info", description: "Nodes cordoned or failing their Ready condition.", recommendation: "Confirm the state is intentional (maintenance) or repair the node." });
    const cp = ds.version ? parseVersion(ds.version.gitVersion) : null;
    if (!cp) skipped.push({ check: "cluster.kubelet_skew", reason: "no /version JSON (kubectl get --raw /version) to compare kubelets against" });
    else {
      const rows = [];
      for (const n of K("Node")) {
        const kv = parseVersion(get(n, "status.nodeInfo.kubeletVersion"));
        if (!kv || kv.major !== cp.major) continue;
        const behind = cp.minor - kv.minor;
        if (behind > o.kubeletSkewMinors || behind < 0) rows.push({ node: n.metadata.name, kubelet: kv.text, controlPlane: cp.text, minorsBehind: behind });
      }
      aggregate("cluster.kubelet_skew", rows, { title: "Kubelet versions outside the supported skew", severity: "medium",
        description: "Kubelets more than " + o.kubeletSkewMinors + " minor versions behind (or ahead of) the API server are unsupported and miss security fixes.", recommendation: "Upgrade the node pools to within the supported version skew." });
    }
  }
  if (gate("cluster.version_eol")) {
    const cp = parseVersion(ds.version.gitVersion);
    const entry = o.eol && Array.isArray(o.eol.cycles) ? o.eol : o.eol && Array.isArray(o.eol.data) ? o.eol.data.find((p) => p.product === "kubernetes") : null;
    if (!cp) skipped.push({ check: "cluster.version_eol", reason: "unparseable gitVersion " + ds.version.gitVersion });
    else if (!entry) skipped.push({ check: "cluster.version_eol", reason: "end-of-life data for kubernetes not provided" });
    else if (!now) skipped.push({ check: "cluster.version_eol", reason: "no reference date (opts.now) and no timestamps in the dump" });
    else {
      const cyc = arr(entry.cycles).find((c) => str(c.cycle) === cp.major + "." + cp.minor);
      const day = str(now).slice(0, 10);
      const eol = cyc ? (typeof cyc.eol === "string" ? cyc.eol : cyc.eol === true ? "0000-00-00" : null) : null;
      const oldest = arr(entry.cycles).map((c) => parseVersion(c.cycle)).filter(Boolean).sort((a, b) => a.major - b.major || a.minor - b.minor)[0];
      if (cyc && eol && eol <= day) add("cluster.version_eol", { key: "eol", title: "Kubernetes " + cp.major + "." + cp.minor + " is past end of life", severity: "high",
        description: "The control plane runs " + ds.version.gitVersion + "; upstream support for " + cyc.cycle + " ended " + (eol === "0000-00-00" ? "" : eol) + " (endoflife.date). Latest patch in the cycle: " + str(cyc.latest) + ".", recommendation: "Upgrade to a supported minor version.",
        evidence: [{ gitVersion: ds.version.gitVersion, cycle: cyc.cycle, eol, latest: str(cyc.latest), referenceDate: day }] });
      else if (!cyc && oldest && (cp.major < oldest.major || (cp.major === oldest.major && cp.minor < oldest.minor))) add("cluster.version_eol", { key: "eol", title: "Kubernetes " + cp.major + "." + cp.minor + " is older than every tracked release", severity: "high",
        description: ds.version.gitVersion + " predates the oldest cycle in the end-of-life data (" + oldest.text + ").", recommendation: "Upgrade to a supported minor version.", evidence: [{ gitVersion: ds.version.gitVersion, oldestTracked: oldest.text, referenceDate: day }] });
      else if (cyc && cyc.latest && cp.patch != null && parseVersion(cyc.latest) && parseVersion(cyc.latest).patch > cp.patch) add("cluster.version_eol", { key: "patch", title: "Kubernetes " + ds.version.gitVersion + " is behind the latest patch " + cyc.latest, severity: "low",
        description: "Patch releases carry security fixes.", recommendation: "Apply the latest patch release for " + cyc.cycle + ".", evidence: [{ gitVersion: ds.version.gitVersion, latest: cyc.latest, eol: str(eol) }] });
    }
  }
  if (gate("cluster.events")) {
    aggregate("cluster.events", K("Event").map((e) => ({ e, count: Number(e.count || get(e, "series.count") || 1) })).filter(({ e, count }) => /^(BackOff|Failed)/.test(str(e.reason)) && count >= o.eventRepeatCount)
      .map(({ e, count }) => ({ namespace: str(e.metadata.namespace), object: str(get(e, "involvedObject.kind")) + "/" + str(get(e, "involvedObject.name")), reason: str(e.reason), count, message: str(e.message).slice(0, 200) })),
      { title: "Repeated BackOff / Failed events", severity: "info", description: "Crash loops and repeated failures (image pulls, mounts, scheduling).", recommendation: "Investigate the involved objects; crash loops can hide a broken security control or a probe misconfiguration." });
  }
  if (gate("cluster.cronjob_hygiene")) {
    aggregate("cluster.cronjob_hygiene", K("CronJob").filter((c) => str(get(c, "spec.concurrencyPolicy") || "Allow") === "Allow" && get(c, "spec.successfulJobsHistoryLimit") == null && get(c, "spec.failedJobsHistoryLimit") == null)
      .map((c) => ({ namespace: c.metadata.namespace, cronJob: c.metadata.name, schedule: str(get(c, "spec.schedule")), concurrencyPolicy: str(get(c, "spec.concurrencyPolicy") || "Allow (default)") })),
      { title: "CronJobs allow overlapping runs with default history", severity: "info", description: "concurrencyPolicy Allow lets runs pile up when a job hangs.", recommendation: "Set concurrencyPolicy: Forbid (or Replace) and explicit history limits." });
  }
  if (gate("cluster.pv")) {
    aggregate("cluster.pv", K("PersistentVolume").filter((p) => get(p, "spec.hostPath") || get(p, "spec.persistentVolumeReclaimPolicy") === "Retain")
      .map((p) => ({ persistentVolume: p.metadata.name, hostPath: str(get(p, "spec.hostPath.path")), reclaimPolicy: str(get(p, "spec.persistentVolumeReclaimPolicy")), claim: get(p, "spec.claimRef") ? str(get(p, "spec.claimRef.namespace")) + "/" + str(get(p, "spec.claimRef.name")) : "" })),
      { title: "PersistentVolumes with hostPath or Retain policy", severity: "info", description: "hostPath PVs write to node disks; Retain keeps released data around after the claim is deleted.", recommendation: "Use a CSI storage class; review retained volumes for data that should be wiped." });
  }

  // ---- kube-bench ----------------------------------------------------------------
  const kb = { pass: 0, fail: 0, warn: 0, info: 0 };
  if (gate("kubebench")) {
    const acc = new Map();
    for (const c of ds.kubeBench.Controls) for (const t of arr(c.tests)) for (const r of arr(t.results)) {
      const st = str(r.status).toUpperCase();
      if (st === "PASS") { kb.pass++; continue; } if (st === "INFO") { kb.info++; continue; }
      if (st !== "FAIL" && st !== "WARN") continue;
      kb[st.toLowerCase()]++;
      const id = str(r.test_number), nt = str(c.node_type).toLowerCase();
      let sev = "low";
      if (st === "FAIL") sev = /^(master|controlplane|etcd)$/.test(nt) ? "high" : nt === "policies" ? (/^5\.1\.(1|3)$/.test(id) || /^5\.2\.(2|3|4|5)$/.test(id) ? "high" : "medium") : "medium";
      const key = id + ":" + st;
      const prev = acc.get(key);
      const ev = { section: str(t.section) + " " + str(t.desc), node_type: str(c.node_type), status: st, scored: r.scored === false ? "no" : "yes", audit: str(r.audit).slice(0, 300), actual_value: str(r.actual_value).slice(0, 300), expected_result: str(r.expected_result).slice(0, 200) };
      if (prev) { prev.evidence.push(ev); continue; }
      acc.set(key, { id, st, sev, desc: str(r.test_desc), rem: str(r.remediation), version: str(c.version), evidence: [ev] });
    }
    const verCmp = (a, b) => { const x = a.split("."), y = b.split("."); for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (+x[i] || 0) - (+y[i] || 0); if (d) return d; } return 0; };
    for (const v of Array.from(acc.values()).sort((a, b) => verCmp(a.id, b.id) || cmp(a.st, b.st))) {
      add("kubebench", { key: v.id + ":" + v.st, title: "CIS " + v.id + " " + v.st + ": " + v.desc, severity: v.sev, confidence: v.st === "FAIL" ? "confirmed" : "review",
        description: "kube-bench reported " + v.st + " for CIS Kubernetes Benchmark " + v.id + (v.version ? " (" + v.version + ")" : "") + ": " + v.desc + ".",
        recommendation: v.rem || "See the CIS Kubernetes Benchmark text for " + v.id + ".",
        controls: [{ framework: "CIS Kubernetes Benchmark" + (v.version ? " (" + v.version + ")" : ""), id: v.id }], evidence: v.evidence, path: "kube-bench " + v.id, tags: ["kube-bench"] });
    }
  }

  // ---- can-i spot checks --------------------------------------------------------
  const caniSubjects = [];
  if (gate("cani")) {
    for (const s of ds.canI) {
      const rows = s.rows.filter((r) => r.resource).map((r) => {
        const m = /^([^./]+|\*)(?:\.([^/]+))?(\/.+)?$/.exec(r.resource) || [];
        return { row: r, rule: { apiGroups: [m[2] == null ? "" : m[2]], resources: [str(m[1]) + str(m[3] || "")], verbs: r.verbs, resourceNames: r.resourceNames } };
      });
      const rules = rows.map((x) => x.rule);
      const perms = dangerousPerms(rules);
      caniSubjects.push({ kind: "can-i", name: s.subject, namespace: "", roles: "", bindings: "", scope: "can-i --list", clusterAdmin: perms.some((p) => p.key === "wildcard" && !p.scoped) ? "yes" : "no", dangerous: perms.map((p) => p.label).join("; "), source: "can-i" });
      if (!perms.length) continue;
      add("cani", { key: s.subject, title: "can-i: " + s.subject + " holds " + perms.map((p) => p.label).join(", "), severity: perms.reduce((a, p) => sevMax(a, p.sev), "low"),
        description: "`kubectl auth can-i --list` for " + s.subject + " shows: " + perms.map((p) => p.label + (p.scoped ? " (named resources)" : "")).join("; ") + ".",
        recommendation: "Confirm the subject needs each right; trim the bindings that grant it.",
        evidence: rows.filter((x) => dangerousPerms([x.rule]).length).map(({ row: r }) => ({ resource: r.resource, resourceNames: r.resourceNames.join(" "), verbs: r.verbs.join(" ") })), tags: ["can-i"] });
    }
  }

  // ---- Tables ----------------------------------------------------------------------
  progress(objects.length, objects.length, "building tables");
  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmp(a.category, b.category) || cmp(a.title, b.title) || cmp(a.id, b.id));
  const perAsset = new Map(), perNs = new Map();
  for (const f of findings) {
    if (f.severity === "info") continue;
    for (const a of f.assets) perAsset.set(a.name, (perAsset.get(a.name) || 0) + 1);
    for (const n of f.namespaces) perNs.set(n, (perNs.get(n) || 0) + 1);
  }
  const tWorkloads = workloads.map((w) => ({
    namespace: w.namespace, kind: w.kind, name: w.name, replicas: w.replicas == null ? "" : w.replicas, images: w.images.join(" "), serviceAccount: w.sa,
    privileged: w.privileged ? "yes" : "no", hostNetwork: w.spec.hostNetwork === true ? "yes" : "no", runAsRoot: w.root === "uid0" ? "yes" : w.root === "possible" ? "possible" : "no",
    policyCoverage: w.coverage, exposure: w.expo, exposedVia: w.exposure.join("; "), saPermissions: w.saClusterAdmin ? "cluster-admin" : w.saPerms.join("; "), findings: perAsset.get(cluster + "/" + w.ref) || 0, system: w.system ? "yes" : "no",
  }));
  const tSubjects = Array.from(graph.subjects.values()).map((s) => ({
    kind: s.kind, name: s.name, namespace: s.namespace, roles: uniq(s.roles).join("; "), bindings: uniq(s.bindings).join("; "), scope: s.clusterWide ? "cluster" : "namespace",
    clusterAdmin: s.clusterAdmin ? "yes" : "no", dangerous: Array.from(s.perms.keys()).sort().join("; "), source: "rbac",
  })).sort((a, b) => cmp(a.kind, b.kind) || cmp(a.namespace, b.namespace) || cmp(a.name, b.name)).concat(caniSubjects);
  const nsNames = uniq(K("Namespace").map((n) => n.metadata.name).concat(Array.from(nsWorkloads.keys())));
  const nsObj = new Map(K("Namespace").map((n) => [n.metadata.name, n]));
  const tNamespaces = nsNames.map((n) => {
    const lab = (nsObj.get(n) && nsObj.get(n).metadata.labels) || {};
    const pols = nsPolicies.get(n) || [];
    return { namespace: n, workloads: (nsWorkloads.get(n) || []).length, networkPolicies: has("NetworkPolicy") ? pols.length : "unknown", defaultDenyIngress: pols.some((p) => isDefaultDeny(p, "Ingress")) ? "yes" : "no", defaultDenyEgress: pols.some((p) => isDefaultDeny(p, "Egress")) ? "yes" : "no",
      psaEnforce: str(lab["pod-security.kubernetes.io/enforce"]) || (nsObj.has(n) ? "(none)" : "unknown"), psaWarn: str(lab["pod-security.kubernetes.io/warn"]), psaAudit: str(lab["pod-security.kubernetes.io/audit"]), findings: perNs.get(n) || 0 };
  });
  const imgMap = new Map();
  for (const w of workloads) for (const img of w.images) (imgMap.get(img) || imgMap.set(img, []).get(img)).push(w);
  const tImages = Array.from(imgMap.keys()).sort().map((img) => {
    const p = parseImage(img), ws = imgMap.get(img);
    return { image: img, registry: p.registry, repository: p.repository, tag: p.tag || "", digest: p.digest ? "yes" : "no", tagPolicy: p.digest ? "pinned (digest)" : p.floating ? "floating" : "tagged", allowed: allowed.length ? (allowed.some((a) => (p.registry + "/" + p.repository).startsWith(a) || p.registry === a) ? "yes" : "no") : "no list", workloads: ws.length, usedBy: ws.map((w) => w.namespace + "/" + w.kind + "/" + w.name).join("; ") };
  });
  exposureRows.sort((a, b) => SEV_RANK[b.severity || "info"] - SEV_RANK[a.severity || "info"] || (!!b.severity - !!a.severity) || cmp(a.namespace, b.namespace) || cmp(a.service, b.service) || cmp(a.workload, b.workload));

  const summary = {
    objects: objects.length, kinds: ds.stats.kinds || {}, namespaces: nsNames.length, workloads: workloads.length,
    privileged: workloads.filter((w) => w.privileged).length, privilegedNonSystem: workloads.filter((w) => w.privileged && !w.system).length,
    clusterAdminSubjects: tSubjects.filter((s) => s.clusterAdmin === "yes" && s.source === "rbac" && !(s.kind === "Group" && s.name === "system:masters")).length,
    namespacesWithoutNetpol: has("NetworkPolicy") ? Array.from(nsWorkloads.keys()).filter((n) => !SYSTEM_NS.includes(n) && !(nsPolicies.get(n) || []).length).length : null,
    externallyExposed: workloads.filter(external).length, findings: findings.length,
    bySeverity: Object.fromEntries(["critical", "high", "medium", "low", "info"].map((s) => [s, findings.filter((f) => f.severity === s).length])),
    kubeBench: ds.kubeBench ? kb : null, version: ds.version ? ds.version.gitVersion : null, referenceDate: now,
  };
  const rem = {
    namespaces: Array.from(remediation.namespaces.entries()).sort((a, b) => cmp(a[0], b[0])).map(([ns, v]) => ({ namespace: ns, ...v })),
    workloads: Array.from(remediation.workloads.values()).sort((a, b) => cmp(a.ref, b.ref)).map((w) => ({ ref: w.ref, base: w.base, containers: Array.from(w.containers.entries()).sort((a, b) => cmp(a[0], b[0])).map(([name, sc]) => ({ name, securityContext: sc })) })),
  };
  skipped.sort((a, b) => cmp(str(a.check), str(b.check)) || cmp(str(a.file), str(b.file)));
  return {
    summary, findings, skipped,
    tables: { workloads: tWorkloads, subjects: tSubjects, namespaces: tNamespaces, images: tImages, exposure: exposureRows },
    remediation: rem,
    meta: { tool: TOOL_ID, version: VERSION, cluster, objects: objects.length, files: ds.files || [], stats: ds.stats || {}, allowedRegistries: allowed, eolUpdated: o.eol && o.eol.updated ? o.eol.updated : null },
  };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
const q = (v) => { const s = v == null ? "" : String(v); return /[",\r\n]/.test(s) || /^[=+\-@\t\r]/.test(s) ? '"' + (/^[=+\-@\t\r]/.test(s) ? "'" : "") + s.replace(/"/g, '""') + '"' : s; };
const csv = (cols, rows) => [cols.join(","), ...rows.map((r) => cols.map((c) => q(r[c])).join(","))].join("\n") + "\n";

export const FINDING_COLS = ["severity", "confidence", "category", "check", "title", "description", "recommendation", "controls", "evidenceCount", "assets", "path"];
/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  return csv(FINDING_COLS, (findings || []).map((f) => ({
    ...f, controls: arr(f.controls).map((c) => c.framework + " " + c.id).join("; "),
    evidenceCount: f.evidenceCount != null ? f.evidenceCount : arr(f.evidence).length,
    assets: arr(f.assets).map((a) => a.type + ":" + a.name).join("; "),
  })));
}

export const WORKLOAD_COLS = ["namespace", "kind", "name", "replicas", "images", "serviceAccount", "privileged", "hostNetwork", "runAsRoot", "policyCoverage", "exposure", "exposedVia", "saPermissions", "findings", "system"];
/** Workload inventory CSV. */
export function workloadsToCsv(rows) { return csv(WORKLOAD_COLS, rows || []); }

/** RBAC matrix CSV: one row per subject, one column per dangerous permission (cell = where it is granted). */
export function rbacMatrixCsv(subjects) {
  const cols = ["kind", "name", "namespace", "scope", "clusterAdmin", "source", ...DANGEROUS.map((d) => d.label), "roles", "bindings"];
  return csv(cols, (subjects || []).map((s) => {
    const r = { ...s };
    const parts = str(s.dangerous).split("; ").filter(Boolean);
    for (const d of DANGEROUS) {
      const hits = parts.filter((p) => p === d.label || p.startsWith(d.label + " "));
      r[d.label] = hits.map((p) => (p === d.label ? "cluster" : p.slice(d.label.length + 1).replace(/^\(|\)$/g, ""))).join(" | ");
    }
    return r;
  }));
}

/** Remediation YAML: a default-deny NetworkPolicy per flagged namespace and a securityContext patch per flagged workload. */
export function remediationYaml(result) {
  const rem = (result && result.remediation) || { namespaces: [], workloads: [] };
  const out = ["# Remediation drafts generated by Kubernetes Audit (" + TOOL_ID + " " + VERSION + ").", "# Review before applying: default-deny blocks traffic until allow rules are added (DNS egress included).", ""];
  for (const n of rem.namespaces) {
    const types = [n.ingress && "Ingress", n.egress && "Egress"].filter(Boolean);
    out.push("---", "apiVersion: networking.k8s.io/v1", "kind: NetworkPolicy", "metadata:", "  name: default-deny-" + types.join("-").toLowerCase(), "  namespace: " + scalar(n.namespace), "spec:", "  podSelector: {}", "  policyTypes:", ...types.map((t) => "  - " + t));
    if (n.egress) out.push("---", "# Allow DNS so pods in " + n.namespace + " can still resolve names after the egress deny.", "apiVersion: networking.k8s.io/v1", "kind: NetworkPolicy", "metadata:", "  name: allow-dns-egress", "  namespace: " + scalar(n.namespace), "spec:", "  podSelector: {}", "  policyTypes:", "  - Egress", "  egress:", "  - to:", "    - namespaceSelector:", "        matchLabels:", "          kubernetes.io/metadata.name: kube-system", "    ports:", "    - port: 53", "      protocol: UDP", "    - port: 53", "      protocol: TCP");
  }
  for (const w of rem.workloads) {
    out.push("---", "# " + w.ref + ": merge into " + w.base + " (kubectl patch --type strategic or edit the manifest)", "# Run as a non-root UID the image supports; mount emptyDir where the app must write.");
    out.push(toYaml({ spec: { securityContext: { seccompProfile: { type: "RuntimeDefault" } }, containers: w.containers.map((c) => ({ name: c.name, securityContext: c.securityContext })) } }));
  }
  if (!rem.namespaces.length && !rem.workloads.length) out.push("# Nothing to remediate: no namespace lacks a default-deny policy and no workload needs a securityContext change.");
  return out.join("\n") + "\n";
}

/** Plain-text summary for the TXT export. */
export function summaryText(result) {
  const s = result.summary;
  const lines = [
    "Kubernetes Audit summary (" + TOOL_ID + " " + VERSION + ")", "Cluster: " + result.meta.cluster + (s.version ? "  version " + s.version : ""),
    "Objects: " + s.objects + "  namespaces: " + s.namespaces + "  workloads: " + s.workloads,
    "Privileged workloads: " + s.privileged + " (" + s.privilegedNonSystem + " outside known system components)",
    "cluster-admin subjects: " + s.clusterAdminSubjects + "  externally exposed workloads: " + s.externallyExposed,
    "Namespaces with workloads but no NetworkPolicy: " + (s.namespacesWithoutNetpol == null ? "not evaluated" : s.namespacesWithoutNetpol),
    "Findings: " + s.findings + "  " + Object.entries(s.bySeverity).map(([k, v]) => k + " " + v).join(", "),
  ];
  if (s.kubeBench) lines.push("kube-bench: " + s.kubeBench.fail + " FAIL, " + s.kubeBench.warn + " WARN, " + s.kubeBench.pass + " PASS");
  if (result.skipped.length) lines.push("", "Skipped checks:", ...result.skipped.map((k) => "- " + k.check + (k.file ? " [" + k.file + "]" : "") + ": " + k.reason));
  lines.push("", "Findings:");
  for (const f of result.findings) lines.push("- [" + f.severity + "/" + f.confidence + "] " + f.title + " (" + f.controls.map((c) => c.framework + " " + c.id).join("; ") + ")", "  " + f.recommendation);
  return lines.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Synthetic example (seeded; clearly labelled; not real data)
// ---------------------------------------------------------------------------
/** Synthetic cluster dump (kubectl List JSON), kube-bench JSON and /version JSON. */
export function exampleDataset(seed = 7) {
  let s = seed >>> 0 || 7;
  const rnd = () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s; };
  const hex = (n) => { let o = ""; while (o.length < n) o += rnd().toString(16).padStart(8, "0"); return o.slice(0, n); };
  const uid = () => hex(8) + "-" + hex(4) + "-4" + hex(3) + "-8" + hex(3) + "-" + hex(12);
  const ts = (d) => "2026-" + d + "T09:00:00Z";
  const md = (name, namespace, extra = {}) => ({ name, ...(namespace ? { namespace } : {}), uid: uid(), resourceVersion: String(1000 + (rnd() % 9000)), creationTimestamp: ts(extra.day || "06-01"), ...(extra.labels ? { labels: extra.labels } : {}), ...(extra.annotations ? { annotations: extra.annotations } : {}), ...(extra.ownerReferences ? { ownerReferences: extra.ownerReferences } : {}) });
  const tpl = (labels, spec) => ({ metadata: { labels }, spec });
  const hardened = { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, runAsNonRoot: true, runAsUser: 10001, capabilities: { drop: ["ALL"] } };
  const limits = { limits: { cpu: "500m", memory: "256Mi" }, requests: { cpu: "100m", memory: "128Mi" } };
  const probe = { httpGet: { path: "/healthz", port: 8080 }, periodSeconds: 10 };
  const frontendUid = uid(), rsUid = uid();
  const items = [
    { apiVersion: "v1", kind: "Namespace", metadata: md("kube-system", null, { day: "01-10", labels: { "kubernetes.io/metadata.name": "kube-system" } }), spec: { finalizers: ["kubernetes"] }, status: { phase: "Active" } },
    { apiVersion: "v1", kind: "Namespace", metadata: md("payments", null, { day: "02-01", labels: { "kubernetes.io/metadata.name": "payments", "pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "latest" } }), spec: { finalizers: ["kubernetes"] }, status: { phase: "Active" } },
    { apiVersion: "v1", kind: "Namespace", metadata: md("web", null, { day: "02-01", labels: { "kubernetes.io/metadata.name": "web" } }), spec: { finalizers: ["kubernetes"] }, status: { phase: "Active" } },
    // kube-system
    { apiVersion: "apps/v1", kind: "DaemonSet", metadata: md("calico-node", "kube-system", { labels: { "k8s-app": "calico-node" } }), spec: { selector: { matchLabels: { "k8s-app": "calico-node" } }, template: tpl({ "k8s-app": "calico-node" }, {
      hostNetwork: true, serviceAccountName: "calico-node", containers: [{ name: "calico-node", image: "docker.io/calico/node:v3.28.1", securityContext: { privileged: true }, resources: { requests: { cpu: "250m" } }, livenessProbe: probe,
        volumeMounts: [{ name: "lib-modules", mountPath: "/lib/modules", readOnly: true }, { name: "var-run-calico", mountPath: "/var/run/calico" }] }],
      volumes: [{ name: "lib-modules", hostPath: { path: "/lib/modules", type: "" } }, { name: "var-run-calico", hostPath: { path: "/var/run/calico", type: "" } }] }) }, status: { desiredNumberScheduled: 2, numberReady: 1 } },
    { apiVersion: "apps/v1", kind: "Deployment", metadata: md("coredns", "kube-system", { labels: { "k8s-app": "kube-dns" } }), spec: { replicas: 2, selector: { matchLabels: { "k8s-app": "kube-dns" } }, template: tpl({ "k8s-app": "kube-dns" }, {
      serviceAccountName: "coredns", securityContext: { seccompProfile: { type: "RuntimeDefault" } }, containers: [{ name: "coredns", image: "registry.k8s.io/coredns/coredns:v1.11.1", args: ["-conf", "/etc/coredns/Corefile"], resources: { limits: { cpu: "200m", memory: "170Mi" } },
        securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { add: ["NET_BIND_SERVICE"], drop: ["ALL"] } }, livenessProbe: probe, readinessProbe: probe }] }) } },
    { apiVersion: "v1", kind: "Service", metadata: md("kube-dns", "kube-system", { labels: { "k8s-app": "kube-dns" } }), spec: { type: "ClusterIP", clusterIP: "10.96.0.10", selector: { "k8s-app": "kube-dns" }, ports: [{ name: "dns", port: 53, protocol: "UDP" }] } },
    { apiVersion: "v1", kind: "ServiceAccount", metadata: md("calico-node", "kube-system") },
    { apiVersion: "v1", kind: "ServiceAccount", metadata: md("coredns", "kube-system") },
    { apiVersion: "v1", kind: "Secret", metadata: md("regcred", "kube-system"), type: "kubernetes.io/dockerconfigjson", data: { ".dockerconfigjson": "eyJhdXRocyI6e319" } },
    // payments
    { apiVersion: "apps/v1", kind: "Deployment", metadata: md("api", "payments", { labels: { app: "api" } }), spec: { replicas: 3, selector: { matchLabels: { app: "api" } }, template: tpl({ app: "api" }, {
      serviceAccountName: "payments-api", automountServiceAccountToken: false, securityContext: { runAsNonRoot: true, seccompProfile: { type: "RuntimeDefault" } },
      containers: [{ name: "api", image: "registry.test.darknode.ai/payments/api:2.4.1@sha256:" + hex(64), ports: [{ containerPort: 8080, protocol: "TCP" }], resources: limits, securityContext: hardened, livenessProbe: probe, readinessProbe: probe,
        env: [{ name: "DB_PASSWORD", valueFrom: { secretKeyRef: { name: "ledger-db", key: "password" } } }, { name: "LOG_LEVEL", value: "info" }] }] }) } },
    { apiVersion: "apps/v1", kind: "StatefulSet", metadata: md("ledger", "payments", { labels: { app: "ledger" } }), spec: { replicas: 1, serviceName: "ledger", selector: { matchLabels: { app: "ledger" } }, template: tpl({ app: "ledger" }, {
      securityContext: { runAsUser: 999, runAsNonRoot: true, fsGroup: 999 },
      containers: [{ name: "postgres", image: "postgres:16.4", ports: [{ containerPort: 5432 }], securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: ["ALL"] } }, readinessProbe: { exec: { command: ["pg_isready"] } },
        env: [{ name: "POSTGRES_USER", value: "ledger" }, { name: "POSTGRES_PASSWORD", value: "Ledger-" + hex(10) }] }] }) } },
    { apiVersion: "v1", kind: "Service", metadata: md("api", "payments"), spec: { type: "ClusterIP", selector: { app: "api" }, ports: [{ port: 80, targetPort: 8080, protocol: "TCP" }] } },
    { apiVersion: "networking.k8s.io/v1", kind: "Ingress", metadata: md("api", "payments", { annotations: { "nginx.ingress.kubernetes.io/ssl-redirect": "true" } }), spec: { ingressClassName: "nginx", tls: [{ hosts: ["api.test.darknode.ai"], secretName: "api-tls" }], rules: [{ host: "api.test.darknode.ai", http: { paths: [{ path: "/", pathType: "Prefix", backend: { service: { name: "api", port: { number: 80 } } } }] } }] } },
    { apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: md("default-deny", "payments"), spec: { podSelector: {}, policyTypes: ["Ingress", "Egress"] } },
    { apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: md("allow-api-ingress", "payments"), spec: { podSelector: { matchLabels: { app: "api" } }, policyTypes: ["Ingress"], ingress: [{ ports: [{ port: 8080, protocol: "TCP" }] }] } },
    { apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: md("allow-ledgr", "payments"), spec: { podSelector: { matchLabels: { app: "ledgr" } }, policyTypes: ["Ingress"], ingress: [{ from: [{ podSelector: { matchLabels: { app: "api" } } }] }] } },
    { apiVersion: "v1", kind: "ServiceAccount", metadata: md("default", "payments"), automountServiceAccountToken: false },
    { apiVersion: "v1", kind: "ServiceAccount", metadata: md("payments-api", "payments") },
    { apiVersion: "v1", kind: "Secret", metadata: md("ledger-db", "payments"), type: "Opaque", data: { password: "TGVkZ2VyUGFzc3dvcmQ=", username: "bGVkZ2Vy" } }, // darknode-ignore: synthetic sample cluster, base64 of a fake password
    { apiVersion: "v1", kind: "Secret", metadata: md("regcred", "payments"), type: "kubernetes.io/dockerconfigjson", data: { ".dockerconfigjson": "eyJhdXRocyI6e319" } },
    // web
    { apiVersion: "apps/v1", kind: "Deployment", metadata: { ...md("frontend", "web", { labels: { app: "frontend" } }), uid: frontendUid }, spec: { replicas: 2, selector: { matchLabels: { app: "frontend" } }, template: tpl({ app: "frontend" }, {
      containers: [{ name: "frontend", image: "registry.test.darknode.ai/web/frontend:1.9.0", ports: [{ containerPort: 80 }], securityContext: { privileged: true, runAsUser: 0 }, resources: limits, readinessProbe: probe }] }) } },
    { apiVersion: "apps/v1", kind: "ReplicaSet", metadata: { ...md("frontend-7d9c6b5f4d", "web", { labels: { app: "frontend" }, ownerReferences: [{ apiVersion: "apps/v1", kind: "Deployment", name: "frontend", uid: frontendUid, controller: true }] }), uid: rsUid }, spec: { replicas: 2, selector: { matchLabels: { app: "frontend" } }, template: tpl({ app: "frontend" }, { containers: [{ name: "frontend", image: "registry.test.darknode.ai/web/frontend:1.9.0", securityContext: { privileged: true, runAsUser: 0 } }] }) } },
    { apiVersion: "v1", kind: "Pod", metadata: md("frontend-7d9c6b5f4d-x2k9p", "web", { labels: { app: "frontend" }, ownerReferences: [{ apiVersion: "apps/v1", kind: "ReplicaSet", name: "frontend-7d9c6b5f4d", uid: rsUid, controller: true }] }), spec: { containers: [{ name: "frontend", image: "registry.test.darknode.ai/web/frontend:1.9.0", securityContext: { privileged: true, runAsUser: 0 } }] }, status: { phase: "Running" } },
    { apiVersion: "apps/v1", kind: "Deployment", metadata: md("cache", "web", { labels: { app: "cache" } }), spec: { replicas: 1, selector: { matchLabels: { app: "cache" } }, template: tpl({ app: "cache" }, { containers: [{ name: "redis", image: "redis:latest", ports: [{ containerPort: 6379 }] }] }) } },
    { apiVersion: "batch/v1", kind: "CronJob", metadata: md("nightly-report", "web"), spec: { schedule: "0 2 * * *", jobTemplate: { spec: { template: tpl({ job: "nightly-report" }, { restartPolicy: "OnFailure", containers: [{ name: "report", image: "registry.test.darknode.ai/web/report:0.3.2", resources: limits, securityContext: hardened }] }) } } } },
    { apiVersion: "v1", kind: "Pod", metadata: md("debug-shell", "web", { day: "09-29", labels: { run: "debug-shell" } }), spec: { hostPID: true, containers: [{ name: "debug-shell", image: "busybox", command: ["sleep", "infinity"], volumeMounts: [{ name: "host", mountPath: "/host" }] }], volumes: [{ name: "host", hostPath: { path: "/", type: "" } }] }, status: { phase: "Running" } },
    { apiVersion: "v1", kind: "Service", metadata: md("frontend", "web"), spec: { type: "LoadBalancer", selector: { app: "frontend" }, ports: [{ port: 80, targetPort: 80, nodePort: 31080, protocol: "TCP" }] }, status: { loadBalancer: { ingress: [{ ip: "203.0.113.20" }] } } },
    { apiVersion: "v1", kind: "Service", metadata: md("legacy", "web"), spec: { type: "ClusterIP", selector: { app: "legacy" }, ports: [{ port: 8080, protocol: "TCP" }] } },
    { apiVersion: "networking.k8s.io/v1", kind: "Ingress", metadata: md("frontend", "web"), spec: { ingressClassName: "nginx", rules: [{ host: "www.test.darknode.ai", http: { paths: [{ path: "/", pathType: "Prefix", backend: { service: { name: "frontend", port: { number: 80 } } } }] } }] } },
    { apiVersion: "v1", kind: "ServiceAccount", metadata: md("default", "web") },
    { apiVersion: "v1", kind: "Secret", metadata: md("regcred", "web"), type: "kubernetes.io/dockerconfigjson", data: { ".dockerconfigjson": "eyJhdXRocyI6e319" } },
    { apiVersion: "v1", kind: "Secret", metadata: md("legacy-token", "web", { annotations: { "kubernetes.io/service-account.name": "default" } }), type: "kubernetes.io/service-account-token", data: { token: "ZXlKaGJHY2lPaUpTVXpJMU5pSjk=", "ca.crt": "LS0tLS1CRUdJTg==", namespace: "d2Vi" } }, // darknode-ignore: synthetic sample cluster, fake service-account token
    { apiVersion: "v1", kind: "ConfigMap", metadata: md("app-config", "web"), data: { DB_PASSWORD: "frontend-" + hex(8), LOG_LEVEL: "debug", FEATURE_FLAGS: "beta" } },
    { apiVersion: "rbac.authorization.k8s.io/v1", kind: "Role", metadata: md("deployer", "web"), rules: [{ apiGroups: [""], resources: ["pods"], verbs: ["create", "delete", "get", "list"] }, { apiGroups: [""], resources: ["pods/exec"], verbs: ["create"] }] },
    { apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding", metadata: md("deployer", "web"), roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "Role", name: "deployer" }, subjects: [{ kind: "ServiceAccount", name: "default", namespace: "web" }] },
    // cluster scope
    { apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRole", metadata: md("cluster-admin", null, { labels: { "kubernetes.io/bootstrapping": "rbac-defaults" } }), rules: [{ apiGroups: ["*"], resources: ["*"], verbs: ["*"] }, { nonResourceURLs: ["*"], verbs: ["*"] }] },
    { apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRole", metadata: md("monitoring"), aggregationRule: { clusterRoleSelectors: [{ matchLabels: { "rbac.test.darknode.ai/aggregate-to-monitoring": "true" } }] }, rules: [] },
    { apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRole", metadata: md("monitoring-secrets", null, { labels: { "rbac.test.darknode.ai/aggregate-to-monitoring": "true" } }), rules: [{ apiGroups: [""], resources: ["secrets", "configmaps"], verbs: ["get", "list", "watch"] }] },
    { apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", metadata: md("cluster-admin", null, { labels: { "kubernetes.io/bootstrapping": "rbac-defaults" } }), roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "ClusterRole", name: "cluster-admin" }, subjects: [{ apiGroup: "rbac.authorization.k8s.io", kind: "Group", name: "system:masters" }] },
    { apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", metadata: md("ops-admin"), roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "ClusterRole", name: "cluster-admin" }, subjects: [{ apiGroup: "rbac.authorization.k8s.io", kind: "User", name: "test@darknode.ai" }] },
    { apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", metadata: md("oncall-everyone", null, { day: "09-28" }), roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "ClusterRole", name: "cluster-admin" }, subjects: [{ apiGroup: "rbac.authorization.k8s.io", kind: "Group", name: "system:authenticated" }] },
    { apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", metadata: md("monitoring"), roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "ClusterRole", name: "monitoring" }, subjects: [{ kind: "ServiceAccount", name: "metrics-agent", namespace: "kube-system" }] },
    { apiVersion: "v1", kind: "Node", metadata: md("node-a", null, { labels: { "kubernetes.io/hostname": "node-a" } }), spec: {}, status: { conditions: [{ type: "Ready", status: "True", reason: "KubeletReady" }], nodeInfo: { kubeletVersion: "v1.30.4", containerRuntimeVersion: "containerd://1.7.20", osImage: "Ubuntu 22.04.4 LTS" } } },
    { apiVersion: "v1", kind: "Node", metadata: md("node-b", null, { labels: { "kubernetes.io/hostname": "node-b" } }), spec: { unschedulable: true }, status: { conditions: [{ type: "Ready", status: "Unknown", reason: "NodeStatusUnknown" }], nodeInfo: { kubeletVersion: "v1.27.9", containerRuntimeVersion: "containerd://1.6.24", osImage: "Ubuntu 20.04.6 LTS" } } },
    { apiVersion: "v1", kind: "PersistentVolume", metadata: md("pv-local-data"), spec: { capacity: { storage: "20Gi" }, accessModes: ["ReadWriteOnce"], hostPath: { path: "/mnt/data" }, persistentVolumeReclaimPolicy: "Retain", claimRef: { namespace: "web", name: "cache-data" } }, status: { phase: "Bound" } },
    { apiVersion: "v1", kind: "Event", metadata: md("debug-shell.17f3a1b2c3d4e5f6", "web", { day: "09-30" }), involvedObject: { kind: "Pod", namespace: "web", name: "debug-shell", apiVersion: "v1" }, reason: "BackOff", message: "Back-off restarting failed container debug-shell in pod debug-shell_web", type: "Warning", count: 14, firstTimestamp: "2026-09-29T10:00:00Z", lastTimestamp: "2026-09-30T08:00:00Z", source: { component: "kubelet", host: "node-a" } },
  ];
  const r = (n, d, st, rem, actual) => ({ test_number: n, test_desc: d, audit: "/bin/ps -ef | grep kube-apiserver | grep -v grep", AuditEnv: "", AuditConfig: "", type: "", remediation: rem, test_info: [rem], status: st, actual_value: actual, scored: true, IsMultiple: false, expected_result: "'--anonymous-auth' is equal to 'false'", reason: "" });
  const bench = { Controls: [
    { id: "1", version: "cis-1.9", detected_version: "1.30", text: "Control Plane Security Configuration", node_type: "master", tests: [{ section: "1.2", type: "", pass: 1, fail: 1, warn: 0, info: 0, desc: "API Server", results: [
      r("1.2.1", "Ensure that the --anonymous-auth argument is set to false (Manual)", "FAIL", "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the control plane node and set --anonymous-auth=false", "anonymous-auth=true"),
      r("1.2.2", "Ensure that the --token-auth-file parameter is not set (Automated)", "PASS", "Do not use token based authentication.", ""),
    ] }], total_pass: 1, total_fail: 1, total_warn: 0, total_info: 0 },
    { id: "4", version: "cis-1.9", detected_version: "1.30", text: "Worker Node Security Configuration", node_type: "node", tests: [{ section: "4.2", type: "", pass: 0, fail: 1, warn: 1, info: 0, desc: "Kubelet", results: [
      { ...r("4.2.1", "Ensure that the --anonymous-auth argument is set to false (Automated)", "FAIL", "If using a Kubelet config file, edit the file to set authentication: anonymous: enabled to false. Restart the kubelet service.", "true"), audit: "/bin/ps -fC kubelet" },
      { ...r("4.2.9", "Ensure that the eventRecordQPS argument is set to a level which ensures appropriate event capture (Manual)", "WARN", "Set eventRecordQPS in the kubelet config file to an appropriate level.", ""), scored: false, expected_result: "" },
    ] }], total_pass: 0, total_fail: 1, total_warn: 1, total_info: 0 },
  ], Totals: { total_pass: 1, total_fail: 2, total_warn: 1, total_info: 0 } };
  const version = { major: "1", minor: "30", gitVersion: "v1.30.4", gitCommit: hex(40), gitTreeState: "clean", buildDate: "2024-08-14T19:23:04Z", goVersion: "go1.22.5", compiler: "gc", platform: "linux/amd64" };
  return {
    label: "Synthetic example cluster (not real data)",
    files: [
      { name: "example-cluster-dump.json", text: JSON.stringify({ apiVersion: "v1", kind: "List", items, metadata: { resourceVersion: "" } }, null, 2) },
      { name: "example-kube-bench.json", text: JSON.stringify(bench, null, 2) },
      { name: "example-version.json", text: JSON.stringify(version, null, 2) },
    ],
    eol: { product: "kubernetes", cycles: [{ cycle: "1.31", releaseDate: "2024-08-13", eol: "2025-11-11", latest: "1.31.14" }, { cycle: "1.30", releaseDate: "2024-04-17", eol: "2025-07-15", latest: "1.30.14" }] },
  };
}

/** Deterministic self-check of the engine against the synthetic example. */
export function selfTest() {
  const tests = [];
  const t = (name, fn) => { let pass = false; try { pass = !!fn(); } catch (_) { pass = false; } tests.push({ name, pass }); };
  const ex = exampleDataset();
  const ds = parseInput(ex.files);
  const r = analyze(ds, { eol: ex.eol });
  const has = (check, pred) => r.findings.some((f) => f.check === check && (!pred || pred(f)));
  t("secret values are stripped at parse time", () => !JSON.stringify(ds).includes("TGVkZ2VyUGFzc3dvcmQ=") && ds.objects.find((o) => o.kind === "Secret" && o.metadata.name === "ledger-db").dataKeys.join() === "password,username");
  t("cluster-admin to system:authenticated is critical", () => has("rbac.cluster_admin", (f) => f.severity === "critical" && f.title.includes("system:authenticated")));
  t("built-in system:masters binding is not flagged", () => !has("rbac.cluster_admin", (f) => f.title.includes("system:masters")));
  t("privileged LoadBalancer workload forms a critical exposure chain", () => has("net.exposed_privileged", (f) => f.severity === "critical" && f.title.includes("web/Deployment/frontend")));
  t("calico privileged DaemonSet is info", () => has("pod.privileged", (f) => f.title.includes("calico-node") && f.severity === "info"));
  t("ReplicaSet and Pod children collapse into the Deployment", () => r.tables.workloads.length === 8);
  t("aggregated ClusterRole inherits secret read", () => has("rbac.dangerous_role", (f) => f.title.includes("monitoring ") && f.description.includes("monitoring-secrets")));
  t("namespace without NetworkPolicy is reported", () => has("net.no_policy", (f) => f.id === "net.no_policy:web"));
  t("kube-bench FAILs map to CIS ids", () => has("kubebench", (f) => f.controls[0].id === "1.2.1" && f.severity === "high") && has("kubebench", (f) => f.controls[0].id === "4.2.1" && f.severity === "medium"));
  t("analysis is deterministic", () => JSON.stringify(analyze(parseInput(ex.files), { eol: ex.eol })) === JSON.stringify(r));
  t("empty input yields no findings", () => analyze(parseInput("")).findings.length === 0);
  return { pass: tests.every((x) => x.pass), tests };
}

/** Per-file classification and totals only (cheap to post back from a Worker). */
export function describeFiles(files, ctx) {
  const ds = parseInput(files);
  if (ctx && ctx.progress) ctx.progress(1, 1, "parsed");
  return { files: ds.files, stats: ds.stats, skipped: ds.skipped };
}
