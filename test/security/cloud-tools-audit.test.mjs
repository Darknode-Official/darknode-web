// Cloud quick tools audit: each test reproduces a wrong verdict, a throw or an
// invalid generated config that the tool produced before its fix.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/cloud.js";

const run = (id, v) => { try { const r = TOOLS.find((t) => t.id === id).run(v, H); return typeof r === "string" ? r : JSON.stringify(r); } catch (e) { return "THROW " + e.message; } };

group("cloud quick tools audit", () => {
  test("Role YAML nests apiGroups/resources/verbs lists under their keys", () => {
    const y = run("cl-k8s-rolebinding-build", { ns: "default", roleName: "reader", apiGroups: '""', resources: "pods", verbs: "get,list", subjectKind: "ServiceAccount", subject: "app-sa" });
    assert.ok(y.includes('  - apiGroups:\n      - ""\n    resources:\n      - pods\n    verbs:\n      - get\n      - list'), y);
  });
  test("IAM lint does not say a Deny s3:* allows every action", () => {
    assert.ok(/^No obvious/.test(run("cl-iam-policy-lint", { json: '{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}' })));
    assert.ok(/MED/.test(run("cl-iam-policy-lint", { json: '{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::b"}]}' })));
  });
  test("policy / SA key tools return an error for JSON null instead of throwing", () => {
    for (const id of ["cl-iam-policy-lint", "cl-iam-policy-explain", "cl-s3-bucket-policy-explain", "cl-gcp-sa-key-explain"]) assert.ok(/"error"/.test(run(id, { json: "null" })), id);
  });
  test("RBAC: get on resources * and watch on secrets both read Secrets", () => {
    assert.ok(/read Secrets/.test(run("cl-k8s-rbac-explain", { apiGroups: '""', resources: "*", verbs: "get,list" })));
    assert.ok(/read Secrets/.test(run("cl-k8s-rbac-explain", { apiGroups: '""', resources: "secrets", verbs: "watch" })));
  });
  test("SAS with spr=https,http is not treated as https-only", () => {
    assert.ok(/WARNING: SAS does not restrict to https/.test(run("cl-azure-sas-explain", { sas: "sv=2022-11-02&sp=r&spr=https,http&sig=x" })));
    assert.ok(!/WARNING/.test(run("cl-azure-sas-explain", { sas: "sv=2022-11-02&sp=r&spr=https&sig=x" })));
  });
  test("SG audit expands port ranges", () => {
    const r = run("cl-sg-audit", { rules: "tcp 0-65535 0.0.0.0/0\ntcp 3300-3400 0.0.0.0/0" });
    assert.ok(/line 1: ALL ports/.test(r) && /3306 \(MySQL/.test(r) && /3389 \(RDP/.test(r), r);
  });
  test("Dockerfile lint: scratch, stage aliases and --platform are not untagged images", () => {
    const r = run("cl-dockerfile-lint", { text: "FROM --platform=linux/amd64 golang:1.22 AS build\nFROM scratch\nFROM build AS t\nUSER 1000\nHEALTHCHECK CMD true" });
    assert.ok(/^No obvious/.test(r), r);
    assert.ok(/line 1: FROM uses/.test(run("cl-dockerfile-lint", { text: "FROM ubuntu\nUSER app\nHEALTHCHECK CMD true" })));
  });
  test("Dockerfile lint: USER in a build stage does not cover the final stage; USER root:root is root", () => {
    assert.ok(/no USER instruction/.test(run("cl-dockerfile-lint", { text: "FROM golang:1.22 AS b\nUSER nobody\nFROM debian:12\nHEALTHCHECK CMD true" })));
    assert.ok(/USER root/.test(run("cl-dockerfile-lint", { text: "FROM debian:12\nUSER root:root\nHEALTHCHECK CMD true" })));
  });
  test("docker run explainer: -u 0 / --user root is root, --volume /:/host is a host-root mount", () => {
    const r = run("cl-docker-run-explain", { cmd: "docker run -u 0 --volume /:/host alpine" });
    assert.ok(!/GOOD/.test(r) && /runs as root/.test(r) && /host root filesystem/.test(r), r);
    assert.ok(/runs as root/.test(run("cl-docker-run-explain", { cmd: "docker run --user=root alpine" })));
    assert.ok(/GOOD/.test(run("cl-docker-run-explain", { cmd: "docker run -u 1000:1000 alpine" })));
  });
  test("Terraform address parser accepts module instance keys", () => {
    const r = run("cl-tf-address-parse", { addr: 'module.vpc[0].aws_subnet.private["a"]' });
    assert.ok(/module path  vpc\[0\]/.test(r) && /type         aws_subnet/.test(r) && /index key    a/.test(r), r);
  });
  test("HCL extractor keeps hyphenated identifiers whole", () => {
    const r = run("cl-hcl-var-extract", { text: "x = module.vpc-main.id\ny = var.my-var" });
    assert.ok(/my-var/.test(r) && /vpc-main\.id/.test(r), r);
  });
  test("compose lint catches a quoted :latest image", () => {
    assert.ok(/:latest/.test(run("cl-compose-lint", { text: 'services:\n  a:\n    image: "nginx:latest"' })));
  });
  test("NetworkPolicy label values are quoted strings (true/1 would not be)", () => {
    const r = run("cl-k8s-netpol-builder", { ns: "default", template: "Allow ingress from pod label", targetLabel: "canary=true", fromLabel: "tier=1", port: "" });
    assert.ok(r.includes('canary: "true"') && r.includes('tier: "1"'), r);
  });
  test("securityContext builder refuses runAsUser 0 with runAsNonRoot", () => {
    assert.ok(/"error"/.test(run("cl-k8s-securitycontext-yaml", { uid: "0", readonly: true })));
    assert.ok(/runAsUser: 1000/.test(run("cl-k8s-securitycontext-yaml", { uid: "1000", readonly: true })));
  });
  test("S3 URL parser handles virtual-hosted URLs for dotted bucket names", () => {
    const r = run("cl-s3-url-parse", { url: "https://my.bucket.s3.us-east-1.amazonaws.com/k" });
    assert.ok(/bucket     my\.bucket/.test(r) && /region     us-east-1/.test(r), r);
    assert.ok(/bucket     b\b/.test(run("cl-s3-url-parse", { url: "https://b.s3.amazonaws.com/k" })));
  });
});
