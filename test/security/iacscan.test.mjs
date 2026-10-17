// IaC Scanner engine tests (public/js/appsec/iacscan-engine.js): one parser
// test per input format (fixtures in the native layout of each tool), rule
// positive/negative pairs, secrets masking, SARIF shape, options, determinism.

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, RULES, DEFAULTS, parseInput, analyze, findingsToCsv, toSarif, toTxt, exampleDataset, selfTest,
  classify, parseDockerfile, scanSecrets, mask, parseImage, policyStatements, IAM_PRIVESC, privescPaths,
} from "../../public/js/appsec/iacscan-engine.js";

const ids = (files, opts) => analyze(files, opts).findings.map((f) => f.ruleId);
const fires = (id, files, opts) => ids(files, opts).includes(id);
const pair = (id, pos, neg) => {
  assert.ok(fires(id, pos), id + " should fire on the positive fixture");
  assert.ok(!fires(id, neg), id + " should stay silent on the negative fixture");
};
const tf = (text) => [{ name: "main.tf", text }];
const k8s = (text) => [{ name: "deploy.yaml", text }];
const df = (text) => [{ name: "Dockerfile", text }];
const compose = (text) => [{ name: "docker-compose.yml", text }];
const wf = (text) => [{ name: ".github/workflows/ci.yml", text }];
const DEPLOY = (container, pod = "") => `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
${pod}      containers:
        - name: web
          image: registry.local/web:1.4.2
${container}`;

/* Fixtures in each tool's native layout */
const TFPLAN = JSON.stringify({
  format_version: "1.2", terraform_version: "1.7.5",
  planned_values: { root_module: {
    resources: [{ address: "aws_s3_bucket.logs", mode: "managed", type: "aws_s3_bucket", name: "logs", provider_name: "registry.terraform.io/hashicorp/aws", schema_version: 0, values: { bucket: "logs-1", acl: "public-read", force_destroy: false, tags: null } }],
    child_modules: [{ address: "module.net", resources: [{ address: "module.net.aws_security_group.web", mode: "managed", type: "aws_security_group", name: "web", provider_name: "registry.terraform.io/hashicorp/aws", schema_version: 1, values: { name: "web", ingress: [{ cidr_blocks: ["0.0.0.0/0"], description: "", from_port: 3389, ipv6_cidr_blocks: [], prefix_list_ids: [], protocol: "tcp", security_groups: [], self: false, to_port: 3389 }] } }] }],
  } },
  resource_changes: [],
}, null, 2);
const TFSTATE = JSON.stringify({
  version: 4, terraform_version: "1.7.5", serial: 3, lineage: "0f2b1c7e-6f0e-4e1b-9d4a-3c2d1e0f9a8b", outputs: {},
  resources: [{ mode: "managed", type: "aws_kms_key", name: "app", provider: "provider[\"registry.terraform.io/hashicorp/aws\"]",
    instances: [{ schema_version: 0, attributes: { arn: "arn:aws:kms:eu-west-1:111122223333:key/1", customer_master_key_spec: "SYMMETRIC_DEFAULT", enable_key_rotation: false, is_enabled: true, key_usage: "ENCRYPT_DECRYPT" }, sensitive_attributes: [] }] }],
  check_results: null,
}, null, 2);
const CFN_YAML = `AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  Public:
    Type: String
Resources:
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: mysql
      DBInstanceClass: db.t3.micro
      PubliclyAccessible: !Ref Public
      StorageEncrypted: true
  Vol:
    Type: AWS::EC2::Volume
    Properties:
      AvailabilityZone: !Select [0, !GetAZs '']
      Size: 10
      Encrypted: false
`;
const CFN_JSON = JSON.stringify({ AWSTemplateFormatVersion: "2010-09-09", Resources: { Sg: { Type: "AWS::EC2::SecurityGroup", Properties: { GroupDescription: "web", SecurityGroupIngress: [{ IpProtocol: "tcp", FromPort: 22, ToPort: 22, CidrIp: "0.0.0.0/0" }] } } } }, null, 2);
const ARM = JSON.stringify({
  $schema: "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#", contentVersion: "1.0.0.0", parameters: {},
  resources: [
    { type: "Microsoft.Storage/storageAccounts", apiVersion: "2023-01-01", name: "stdata01", location: "[resourceGroup().location]", sku: { name: "Standard_LRS" }, kind: "StorageV2", properties: { supportsHttpsTrafficOnly: false, minimumTlsVersion: "TLS1_0", allowBlobPublicAccess: true } },
    { type: "Microsoft.Network/networkSecurityGroups", apiVersion: "2023-04-01", name: "nsg-web", location: "westeurope", properties: { securityRules: [{ name: "rdp", properties: { protocol: "Tcp", sourcePortRange: "*", destinationPortRange: "3389", sourceAddressPrefix: "*", destinationAddressPrefix: "*", access: "Allow", priority: 100, direction: "Inbound" } }] } },
  ],
}, null, 2);

group("iacscan: parsers", () => {
  test("Terraform HCL: resource blocks, nested blocks and line numbers", () => {
    const p = parseInput(tf('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  versioning {\n    enabled = true\n  }\n}\n\ndata "aws_iam_policy_document" "d" {\n  statement {\n    actions = ["s3:GetObject"]\n    resources = ["*"]\n  }\n}\n'));
    assert.equal(p.files[0].kind, "terraform");
    assert.equal(p.files[0].confidence, "high");
    const b = p.rows.find((r) => r.id === "aws_s3_bucket.b");
    assert.equal(b.line, 1);
    assert.equal(b.props.versioning[0].enabled, true);
    assert.equal(p.rows.find((r) => r.mode === "data").line, 8);
  });
  test("terraform show -json plan: root and child module resources", () => {
    const p = parseInput([{ name: "plan.json", text: TFPLAN }]);
    assert.equal(p.files[0].kind, "tfplan");
    assert.deepEqual(p.rows.map((r) => r.id).sort(), ["aws_s3_bucket.logs", "module.net.aws_security_group.web"]);
    const f = ids([{ name: "plan.json", text: TFPLAN }]);
    assert.ok(f.includes("AWS-S3-001") && f.includes("AWS-SG-001"));
  });
  test("terraform.tfstate v4: instances[].attributes", () => {
    const p = parseInput([{ name: "terraform.tfstate", text: TFSTATE }]);
    assert.equal(p.files[0].kind, "tfstate");
    assert.equal(p.rows[0].props.enable_key_rotation, false);
    assert.ok(fires("AWS-KMS-001", [{ name: "terraform.tfstate", text: TFSTATE }]));
  });
  test("CloudFormation YAML: intrinsics are not evaluated and are reported as skipped", () => {
    const p = parseInput([{ name: "stack.yaml", text: CFN_YAML }]);
    assert.equal(p.files[0].kind, "cloudformation");
    assert.deepEqual(p.rows.find((r) => r.name === "Db").props.PubliclyAccessible, { "!Ref": "Public" });
    const r = analyze([{ name: "stack.yaml", text: CFN_YAML }]);
    assert.ok(!r.findings.some((f) => f.ruleId === "AWS-RDS-002"), "never reports an unresolved !Ref");
    assert.ok(r.skipped.some((s) => s.check === "AWS-RDS-002" && /not evaluated/.test(s.reason)));
    assert.ok(r.findings.some((f) => f.ruleId === "AWS-EBS-001" && f.line === 18));
  });
  test("CloudFormation JSON template", () => {
    const p = parseInput([{ name: "sg.json", text: CFN_JSON }]);
    assert.equal(p.files[0].kind, "cloudformation");
    assert.ok(fires("AWS-SG-001", [{ name: "sg.json", text: CFN_JSON }]));
  });
  test("Kubernetes multi-document YAML with doc index and kind line", () => {
    const text = DEPLOY("") + "---\napiVersion: v1\nkind: Service\nmetadata:\n  name: web\n  namespace: shop\nspec:\n  type: NodePort\n";
    const p = parseInput(k8s(text));
    assert.equal(p.files[0].kind, "kubernetes");
    assert.equal(p.files[0].docs, 2);
    const svc = p.rows.find((r) => r.type === "Service");
    assert.equal(svc.doc, "1");
    assert.equal(svc.line, 20);
  });
  test("Dockerfile: continuation lines, multi-stage and parser directive", () => {
    const ins = parseDockerfile("# syntax=docker/dockerfile:1\nFROM golang:1.22 AS build\nRUN go build \\\n  -o /out/app \\\n  ./cmd\nFROM gcr.io/distroless/static\nCOPY --from=build /out/app /app\nUSER 65532\n");
    assert.equal(ins.length, 5);
    assert.equal(ins[1].args, "go build -o /out/app ./cmd");
    assert.equal(ins[1].line, 3);
    assert.equal(ins[4].stage, 1);
  });
  test("docker-compose services with line numbers", () => {
    const p = parseInput(compose("services:\n  web:\n    image: nginx:1.27\n  db:\n    image: postgres:16\n"));
    assert.equal(p.files[0].kind, "compose");
    assert.deepEqual(p.rows.map((r) => [r.name, r.line]), [["web", 2], ["db", 4]]);
  });
  test("Azure ARM deploymentTemplate", () => {
    const p = parseInput([{ name: "azuredeploy.json", text: ARM }]);
    assert.equal(p.files[0].kind, "arm");
    assert.equal(p.rows.length, 2);
    const f = ids([{ name: "azuredeploy.json", text: ARM }]);
    for (const id of ["AZ-ST-001", "AZ-ST-003", "AZ-ST-004", "AZ-NSG-002"]) assert.ok(f.includes(id), id);
  });
  test("GitHub Actions workflow under .github/workflows", () => {
    const p = parseInput(wf("name: ci\non: [push]\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"));
    assert.equal(p.files[0].kind, "github-actions");
    assert.deepEqual(p.rows[0].props.on, ["push"]);
  });
  test("unsupported and not-scannable inputs are reported, not guessed", () => {
    assert.equal(classify("main.bicep", "resource sa 'x' = {}").kind, "bicep");
    assert.equal(classify("chart/values.yaml", "image:\n  tag: latest\n").kind, "helm-values");
    assert.equal(classify("templates/deploy.yaml", "kind: Deployment\nspec:\n  replicas: {{ .Values.replicas }}\n").kind, "helm-template");
    const r = analyze([{ name: "main.bicep", text: "param x string" }, { name: "values.yaml", text: "a: 1\n" }]);
    assert.equal(r.findings.length, 0);
    assert.ok(r.skipped.some((s) => /Bicep is not supported/.test(s.reason)));
    assert.ok(r.skipped.some((s) => /not scannable alone/.test(s.reason)));
  });
  test("malformed HCL is reported in skipped with a reason", () => {
    const r = analyze(tf('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n'));
    assert.ok(r.skipped.some((s) => s.check.includes("parse") && /HCL parse error/.test(s.reason)));
  });
});

group("iacscan: AWS rules", () => {
  test("AWS-S3-001 public canned ACL", () => pair("AWS-S3-001", tf('resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'), tf('resource "aws_s3_bucket" "b" {\n  acl = "private"\n}\n')));
  test("AWS-S3-002 public bucket policy", () => pair("AWS-S3-002",
    tf('resource "aws_s3_bucket_policy" "p" {\n  bucket = aws_s3_bucket.b.id\n  policy = jsonencode({\n    Statement = [{\n      Effect = "Allow"\n      Principal = "*"\n      Action = "s3:GetObject"\n      Resource = "arn:aws:s3:::b/*"\n    }]\n  })\n}\n'),
    tf('resource "aws_s3_bucket_policy" "p" {\n  bucket = aws_s3_bucket.b.id\n  policy = jsonencode({\n    Statement = [{\n      Effect = "Allow"\n      Principal = { AWS = "arn:aws:iam::111122223333:root" }\n      Action = "s3:GetObject"\n      Resource = "arn:aws:s3:::b/*"\n    }]\n  })\n}\n')));
  test("AWS-S3-003 public access block linked by reference", () => pair("AWS-S3-003",
    tf('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'),
    tf('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\nresource "aws_s3_bucket_public_access_block" "b" {\n  bucket = aws_s3_bucket.b.id\n  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = true\n}\n')));
  test("AWS-S3-004 versioning via aws_s3_bucket_versioning", () => pair("AWS-S3-004",
    tf('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\nresource "aws_s3_bucket_versioning" "v" {\n  bucket = aws_s3_bucket.b.id\n  versioning_configuration {\n    status = "Suspended"\n  }\n}\n'),
    tf('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\nresource "aws_s3_bucket_versioning" "v" {\n  bucket = aws_s3_bucket.b.id\n  versioning_configuration {\n    status = "Enabled"\n  }\n}\n')));
  test("AWS-RDS-002 publicly accessible database", () => pair("AWS-RDS-002", tf('resource "aws_db_instance" "d" {\n  publicly_accessible = true\n}\n'), tf('resource "aws_db_instance" "d" {\n  publicly_accessible = false\n}\n')));
  test("AWS-RDS-001 unencrypted storage", () => pair("AWS-RDS-001", tf('resource "aws_rds_cluster" "c" {\n  engine = "aurora-postgresql"\n}\n'), tf('resource "aws_rds_cluster" "c" {\n  storage_encrypted = true\n}\n')));
  test("AWS-SG-001 SSH from 0.0.0.0/0 (port ranges)", () => pair("AWS-SG-001",
    tf('resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  from_port = 20\n  to_port = 25\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'),
    tf('resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  from_port = 22\n  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["10.0.0.0/8"]\n}\n')));
  test("AWS-SG-002 RDP from ::/0", () => pair("AWS-SG-002",
    tf('resource "aws_vpc_security_group_ingress_rule" "r" {\n  cidr_ipv6 = "::/0"\n  from_port = 3389\n  to_port = 3389\n  ip_protocol = "tcp"\n}\n'),
    tf('resource "aws_vpc_security_group_ingress_rule" "r" {\n  cidr_ipv6 = "::/0"\n  from_port = 443\n  to_port = 443\n  ip_protocol = "tcp"\n}\n')));
  test("AWS-IAM-001 admin wildcard and AWS-IAM-003 PassRole", () => {
    pair("AWS-IAM-001", tf('data "aws_iam_policy_document" "d" {\n  statement {\n    actions = ["*"]\n    resources = ["*"]\n  }\n}\n'), tf('data "aws_iam_policy_document" "d" {\n  statement {\n    actions = ["s3:GetObject"]\n    resources = ["*"]\n  }\n}\n'));
    pair("AWS-IAM-003", tf('resource "aws_iam_role_policy" "p" {\n  policy = "{\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Action\\":\\"iam:PassRole\\",\\"Resource\\":\\"*\\"}]}"\n}\n'), tf('resource "aws_iam_role_policy" "p" {\n  policy = "{\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Action\\":\\"iam:PassRole\\",\\"Resource\\":\\"arn:aws:iam::1:role/x\\"}]}"\n}\n'));
  });
  test("policyStatements parses JSON strings and rejects references", () => {
    assert.equal(policyStatements('{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}')[0].actions[0], "*");
    assert.equal(policyStatements({ ref: "data.aws_iam_policy_document.x.json" }), null);
  });
  test("AWS-CT-001/002 CloudTrail multi-region and validation", () => {
    pair("AWS-CT-001", tf('resource "aws_cloudtrail" "t" {\n  is_multi_region_trail = false\n}\n'), tf('resource "aws_cloudtrail" "t" {\n  is_multi_region_trail = true\n}\n'));
    pair("AWS-CT-002", tf('resource "aws_cloudtrail" "t" {\n  enable_log_file_validation = false\n}\n'), tf('resource "aws_cloudtrail" "t" {\n  enable_log_file_validation = true\n}\n'));
  });
  test("AWS-EC2-001 IMDSv1", () => pair("AWS-EC2-001", tf('resource "aws_instance" "i" {\n  metadata_options {\n    http_tokens = "optional"\n  }\n}\n'), tf('resource "aws_instance" "i" {\n  metadata_options {\n    http_tokens = "required"\n  }\n}\n')));
  test("AWS-LMB-003 Lambda env secret (masked)", () => {
    const key = "AKIA" + "IOSFODNN7EXAMPLE";
    const pos = tf('resource "aws_lambda_function" "f" {\n  environment {\n    variables = {\n      ACCESS = "' + key + '"\n    }\n  }\n}\n');
    pair("AWS-LMB-003", pos, tf('resource "aws_lambda_function" "f" {\n  environment {\n    variables = {\n      DB_PASSWORD = var.db_password\n    }\n  }\n}\n'));
    const f = analyze(pos).findings.find((x) => x.ruleId === "AWS-LMB-003");
    assert.ok(!JSON.stringify(f).includes(key), "full key never appears in the finding");
  });
  test("AWS-ELB-002 weak TLS policy and AWS-ECR-001 mutable tags", () => {
    pair("AWS-ELB-002", tf('resource "aws_lb_listener" "l" {\n  protocol = "HTTPS"\n  ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"\n}\n'), tf('resource "aws_lb_listener" "l" {\n  protocol = "HTTPS"\n  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"\n}\n'));
    pair("AWS-ECR-001", tf('resource "aws_ecr_repository" "r" {\n  name = "x"\n}\n'), tf('resource "aws_ecr_repository" "r" {\n  image_tag_mutability = "IMMUTABLE"\n}\n'));
  });
});

group("iacscan: Azure and GCP rules", () => {
  test("AZ-KV-001 Key Vault purge protection (azurerm)", () => pair("AZ-KV-001", tf('resource "azurerm_key_vault" "k" {\n  name = "kv"\n}\n'), tf('resource "azurerm_key_vault" "k" {\n  purge_protection_enabled = true\n}\n')));
  test("AZ-NSG-001 SSH from Internet (azurerm rule)", () => pair("AZ-NSG-001",
    tf('resource "azurerm_network_security_rule" "r" {\n  direction = "Inbound"\n  access = "Allow"\n  source_address_prefix = "Internet"\n  destination_port_range = "22"\n}\n'),
    tf('resource "azurerm_network_security_rule" "r" {\n  direction = "Inbound"\n  access = "Allow"\n  source_address_prefix = "10.0.0.0/8"\n  destination_port_range = "22"\n}\n')));
  test("AZ-SQL-002 firewall 0.0.0.0-255.255.255.255", () => pair("AZ-SQL-002",
    tf('resource "azurerm_mssql_firewall_rule" "f" {\n  start_ip_address = "0.0.0.0"\n  end_ip_address = "255.255.255.255"\n}\n'),
    tf('resource "azurerm_mssql_firewall_rule" "f" {\n  start_ip_address = "203.0.113.10"\n  end_ip_address = "203.0.113.10"\n}\n')));
  test("GCP-GCS-001 allUsers on a bucket", () => pair("GCP-GCS-001", tf('resource "google_storage_bucket_iam_member" "m" {\n  role = "roles/storage.objectViewer"\n  member = "allUsers"\n}\n'), tf('resource "google_storage_bucket_iam_member" "m" {\n  member = "group:ops@example.com"\n}\n')));
  test("GCP-FW-001 firewall SSH from 0.0.0.0/0", () => pair("GCP-FW-001",
    tf('resource "google_compute_firewall" "f" {\n  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "tcp"\n    ports = ["22"]\n  }\n}\n'),
    tf('resource "google_compute_firewall" "f" {\n  source_ranges = ["35.235.240.0/20"]\n  allow {\n    protocol = "tcp"\n    ports = ["22"]\n  }\n}\n')));
  test("GCP-CE-001 default service account with cloud-platform scope", () => pair("GCP-CE-001",
    tf('resource "google_compute_instance" "i" {\n  service_account {\n    scopes = ["cloud-platform"]\n  }\n}\n'),
    tf('resource "google_compute_instance" "i" {\n  service_account {\n    email = "app@p.iam.gserviceaccount.com"\n    scopes = ["cloud-platform"]\n  }\n}\n')));
  test("GCP-SQL-001 authorized network 0.0.0.0/0", () => pair("GCP-SQL-001",
    tf('resource "google_sql_database_instance" "d" {\n  settings {\n    ip_configuration {\n      authorized_networks {\n        name = "all"\n        value = "0.0.0.0/0"\n      }\n    }\n  }\n}\n'),
    tf('resource "google_sql_database_instance" "d" {\n  settings {\n    ip_configuration {\n      ipv4_enabled = false\n    }\n  }\n}\n')));
  test("GCP-GKE-001 legacy ABAC", () => pair("GCP-GKE-001", tf('resource "google_container_cluster" "c" {\n  enable_legacy_abac = true\n}\n'), tf('resource "google_container_cluster" "c" {\n  enable_legacy_abac = false\n}\n')));
});

group("iacscan: Kubernetes rules", () => {
  const sc = (body) => "          securityContext:\n" + body;
  test("K8S-001 privileged container with line of the key", () => {
    pair("K8S-001", k8s(DEPLOY(sc("            privileged: true\n"))), k8s(DEPLOY(sc("            privileged: false\n"))));
    const f = analyze(k8s(DEPLOY(sc("            privileged: true\n")))).findings.find((x) => x.ruleId === "K8S-001");
    assert.equal(f.line, 19);
  });
  test("K8S-004 hostNetwork", () => pair("K8S-004", k8s(DEPLOY("", "      hostNetwork: true\n")), k8s(DEPLOY("", "      hostNetwork: false\n"))));
  test("K8S-006 runtime socket hostPath", () => pair("K8S-006",
    k8s(DEPLOY("", "      volumes:\n        - name: sock\n          hostPath:\n            path: /var/run/docker.sock\n")),
    k8s(DEPLOY("", "      volumes:\n        - name: cache\n          emptyDir: {}\n"))));
  test("K8S-014 latest image tag", () => pair("K8S-014", k8s(DEPLOY("").replace("web:1.4.2", "web:latest")), k8s(DEPLOY(""))));
  test("K8S-019 literal secret in env vs K8S-018 secretKeyRef", () => {
    pair("K8S-019", k8s(DEPLOY("          env:\n            - name: DB_PASSWORD\n              value: hunter2-prod\n")), k8s(DEPLOY("          env:\n            - name: DB_PASSWORD\n              valueFrom:\n                secretKeyRef:\n                  name: db\n                  key: password\n")));
    assert.ok(fires("K8S-018", k8s(DEPLOY("          env:\n            - name: DB_PASSWORD\n              valueFrom:\n                secretKeyRef:\n                  name: db\n                  key: password\n"))));
  });
  test("K8S-010 SYS_ADMIN capability", () => pair("K8S-010", k8s(DEPLOY(sc("            capabilities:\n              add: [\"SYS_ADMIN\"]\n"))), k8s(DEPLOY(sc("            capabilities:\n              add: [\"NET_BIND_SERVICE\"]\n              drop: [\"ALL\"]\n")))));
  test("K8S-025 cluster-admin binding and K8S-024 wildcard role", () => {
    pair("K8S-025", k8s("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: ci\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n  - kind: ServiceAccount\n    name: ci\n    namespace: build\n"),
      k8s("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: ci\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: view\nsubjects:\n  - kind: ServiceAccount\n    name: ci\n    namespace: build\n"));
    pair("K8S-024", k8s("apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: r\n  namespace: shop\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"*\"]\n    verbs: [\"*\"]\n"), k8s("apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: r\n  namespace: shop\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"pods\"]\n    verbs: [\"get\", \"list\"]\n"));
  });
  test("K8S-023 Ingress without TLS", () => pair("K8S-023",
    k8s("apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: i\n  namespace: shop\nspec:\n  rules:\n    - host: shop.example.com\n"),
    k8s("apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: i\n  namespace: shop\nspec:\n  tls:\n    - hosts: [shop.example.com]\n      secretName: shop-tls\n  rules:\n    - host: shop.example.com\n")));
});

group("iacscan: Docker, Compose and Actions rules", () => {
  test("DKR-001 no USER / DKR-002 USER root", () => {
    pair("DKR-001", df("FROM alpine:3.20\nRUN echo hi\n"), df("FROM alpine:3.20\nUSER 10001\n"));
    pair("DKR-002", df("FROM alpine:3.20\nUSER root\n"), df("FROM alpine:3.20\nUSER app\n"));
  });
  test("DKR-004 curl | sh across a continuation line", () => {
    pair("DKR-004", df("FROM debian:12\nRUN apt-get update && \\\n    curl -fsSL https://get.example.invalid \\\n    | bash\nUSER 1000\n"), df("FROM debian:12\nRUN curl -fsSLo /tmp/i.sh https://get.example.invalid && sha256sum -c /tmp/i.sha\nUSER 1000\n"));
    const f = analyze(df("FROM debian:12\nRUN apt-get update && \\\n    curl -fsSL https://get.example.invalid \\\n    | bash\n")).findings.find((x) => x.ruleId === "DKR-004");
    assert.equal(f.line, 2);
  });
  test("DKR-006 unpinned FROM ignores stage aliases and scratch", () => {
    pair("DKR-006", df("FROM ubuntu\nUSER 1\n"), df("FROM golang:1.22 AS build\nFROM build\nFROM scratch\nUSER 1\n"));
    assert.deepEqual(parseImage("registry:5000/team/app:1.2@sha256:abc"), { repo: "registry:5000/team/app", tag: "1.2", digest: "sha256:abc" });
  });
  test("DKR-008 secret in ENV / DKR-003 ADD", () => {
    pair("DKR-008", df("FROM alpine:3.20\nENV API_TOKEN=s3cr3t-value-123\nUSER 1\n"), df("FROM alpine:3.20\nENV API_TOKEN_FILE=/run/secrets/token\nUSER 1\n"));
    pair("DKR-003", df("FROM alpine:3.20\nADD https://example.invalid/x.bin /x\n"), df("FROM alpine:3.20\nADD rootfs.tar.gz /\n"));
  });
  test("CMP-005 docker.sock and CMP-002 host network", () => {
    pair("CMP-005", compose("services:\n  agent:\n    image: agent:1.0\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"), compose("services:\n  agent:\n    image: agent:1.0\n    volumes:\n      - ./data:/data\n"));
    pair("CMP-002", compose("services:\n  a:\n    image: a:1\n    network_mode: host\n"), compose("services:\n  a:\n    image: a:1\n    network_mode: bridge\n"));
  });
  test("CMP-007 DB port on all interfaces vs loopback", () => pair("CMP-007", compose("services:\n  db:\n    image: mysql:8\n    ports:\n      - \"3306:3306\"\n"), compose("services:\n  db:\n    image: mysql:8\n    ports:\n      - \"127.0.0.1:3306:3306\"\n")));
  test("CMP-009 literal credentials vs ${VAR}", () => pair("CMP-009", compose("services:\n  db:\n    image: postgres:16\n    environment:\n      - POSTGRES_PASSWORD=supersecret99\n"), compose("services:\n  db:\n    image: postgres:16\n    environment:\n      - POSTGRES_PASSWORD=${PG_PASSWORD}\n")));
  test("GHA-003 unpinned third-party action vs full SHA", () => {
    const base = (u) => wf("name: ci\non: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + u + "\n");
    pair("GHA-003", base("some-org/tool@main"), base("some-org/tool@8f4b7f84864484a7bf31766abe9204da3cbe65b3"));
  });
  test("GHA-005 write-all and GHA-006 missing permissions", () => {
    pair("GHA-005", wf("on: push\npermissions: write-all\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"), wf("on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"));
    pair("GHA-006", wf("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"), wf("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n      - run: make\n"));
  });
  test("GHA-007 script injection and GHA-008 secret echo", () => {
    pair("GHA-007", wf("on: issues\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n"), wf("on: issues\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          TITLE: ${{ github.event.issue.title }}\n        run: echo \"$TITLE\"\n"));
    pair("GHA-008", wf("on: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ secrets.DEPLOY_KEY }}\n"), wf("on: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./deploy.sh\n        env:\n          KEY: ${{ secrets.DEPLOY_KEY }}\n"));
  });
  test("GHA-001 pull_request_target checking out the PR head", () => {
    const w = (ref) => wf("on: pull_request_target\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3\n        with:\n          persist-credentials: false\n" + ref);
    pair("GHA-001", w("          ref: ${{ github.event.pull_request.head.sha }}\n"), w(""));
  });
});

group("iacscan: secrets", () => {
  test("AWS key, private key and GitHub token detected with line numbers and masking", () => {
    const key = "AKIA" + "Z7Q2LMNOPQRSTUVW";
    const gh = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    const text = "# config\naws_access_key_id = " + key + "\n-----BEGIN RSA " + "PRIVATE KEY-----\nMIIE\ntoken: " + gh + "\n";
    const hits = scanSecrets(text);
    const by = Object.fromEntries(hits.map((h) => [h.ruleId, h]));
    assert.equal(by["SEC-001"].line, 2);
    assert.equal(by["SEC-002"].line, 3);
    assert.equal(by["SEC-003"].line, 5);
    assert.equal(by["SEC-001"].masked, "AKIA" + "*".repeat(12) + "VW");
    const r = analyze([{ name: "notes.txt", text }]);
    assert.ok(!JSON.stringify(r).includes(key) && !JSON.stringify(r).includes(gh), "raw secrets never appear in output");
  });
  test("generic password literal fires; references and placeholders do not", () => {
    assert.ok(scanSecrets('db_password = "Tr0ub4dor-prod"').some((h) => h.ruleId === "SEC-006"));
    assert.equal(scanSecrets('db_password = "${var.pw}"\npassword: "<your-password>"\npassword_length = "16"').filter((h) => h.ruleId === "SEC-006").length, 0);
  });
  test("mask keeps first 4 and last 2 characters", () => {
    assert.equal(mask("abcdefghij"), "abcd****ij");
    assert.equal(mask("abc"), "***");
  });
});

group("iacscan: outputs and options", () => {
  const ex = exampleDataset();
  test("rule catalogue: >= 120 rules, unique ids, every rule cites a framework", () => {
    assert.ok(RULES.length >= 120, "rules: " + RULES.length);
    assert.equal(new Set(RULES.map((r) => r.id)).size, RULES.length);
    assert.ok(RULES.every((r) => r.frameworks.length && ["critical", "high", "medium", "low", "info"].includes(r.severity)));
  });
  test("findings follow the contract shape", () => {
    const r = analyze(ex.files);
    for (const f of r.findings) {
      assert.ok(f.title && f.recommendation && f.controls.length && f.file && f.line >= 1 && f.resource);
      assert.ok(["confirmed", "likely", "review"].includes(f.confidence));
      assert.ok(f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length);
      assert.equal(f.assets[0].data.kind, "iac-resource");
    }
  });
  test("tables: every rule listed with hit counts, resources carry rule hits", () => {
    const r = analyze(ex.files);
    assert.equal(r.tables.rules.length, RULES.length);
    assert.ok(r.tables.rules.some((x) => x.hits === 0));
    assert.equal(r.tables.rules.reduce((a, x) => a + x.hits, 0), r.findings.length);
    const sg = r.tables.resources.find((x) => x.type === "aws_security_group");
    assert.ok(sg.rules.includes("AWS-SG-001"));
    assert.ok(r.summary.byPlatform.aws.resources > 0 && r.summary.bySeverity.critical > 0);
  });
  test("SARIF 2.1.0 export is structurally valid", () => {
    const r = analyze(ex.files);
    const s = JSON.parse(JSON.stringify(toSarif(r)));
    assert.equal(s.version, "2.1.0");
    const driver = s.runs[0].tool.driver;
    assert.equal(driver.rules.length, RULES.length);
    assert.equal(s.runs[0].results.length, r.findings.length);
    for (const res of s.runs[0].results) {
      assert.ok(res.ruleId && ["error", "warning", "note"].includes(res.level));
      assert.equal(driver.rules[res.ruleIndex].id, res.ruleId);
      assert.ok(res.locations[0].physicalLocation.artifactLocation.uri && res.locations[0].physicalLocation.region.startLine >= 1);
    }
  });
  test("ignoreRules and minSeverity", () => {
    const all = analyze(ex.files);
    const ig = analyze(ex.files, { ignoreRules: ["AWS-S3-001", "K8S-001"] });
    assert.ok(!ig.findings.some((f) => f.ruleId === "AWS-S3-001" || f.ruleId === "K8S-001"));
    assert.equal(ig.tables.rules.find((x) => x.id === "K8S-001").enabled, false);
    const hi = analyze(ex.files, { minSeverity: "high" });
    assert.ok(hi.findings.length > 0 && hi.findings.every((f) => f.severity === "critical" || f.severity === "high"));
    assert.equal(hi.summary.filteredOut, all.findings.length - hi.findings.length);
  });
  test("analyze is byte-identical across runs and input order", () => {
    const a = JSON.stringify(analyze(ex.files));
    assert.equal(a, JSON.stringify(analyze(ex.files)));
    assert.equal(a, JSON.stringify(analyze(ex.files.slice().reverse())));
  });
  test("progress callback reports done == total at the end", () => {
    const calls = [];
    analyze(ex.files, {}, { progress: (i, n, l) => calls.push([i, n, l]) });
    const last = calls[calls.length - 1];
    assert.ok(calls.length > 1 && last[0] === last[1] && last[2] === "done");
  });
  test("findingsToCsv header and row count; TXT summary", () => {
    const r = analyze(ex.files);
    const csv = findingsToCsv(r.findings).trim().split("\n");
    assert.equal(csv[0], "severity,confidence,rule,title,platform,resource,resource_type,file,line,controls,description,recommendation,evidence_count");
    assert.equal(csv.length, r.findings.length + 1);
    assert.ok(/IaC Scanner summary/.test(toTxt(r)));
  });
  test("example is labelled synthetic in every file and seeded", () => {
    assert.ok(ex.files.every((f) => /SYNTHETIC EXAMPLE/.test(f.text)));
    assert.equal(JSON.stringify(exampleDataset(7)), JSON.stringify(exampleDataset(7)));
    assert.notEqual(JSON.stringify(exampleDataset(7)), JSON.stringify(exampleDataset(8)));
  });
  test("empty input and string input are safe", () => {
    const r = analyze([]);
    assert.equal(r.findings.length, 0);
    assert.equal(r.meta.rows, 0);
    assert.equal(parseInput("").files[0].kind, "empty");
    assert.equal(TOOL_ID, "iacscan");
    assert.equal(DEFAULTS.minSeverity, "info");
  });
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
});

group("iacscan: ported container checks", () => {
  const find = (id, files) => analyze(files).findings.find((x) => x.ruleId === id);
  test("DKR-015 database port EXPOSE is tokenised, not substring-matched", () => {
    pair("DKR-015", df("FROM alpine:3.20\nEXPOSE 8080 5432/tcp\nUSER 1\n"), df("FROM alpine:3.20\nEXPOSE 8080 15432 8022\nUSER 1\n"));
    assert.ok(find("DKR-015", df("FROM alpine:3.20\nEXPOSE 6000-6400\nUSER 1\n")).description.includes("6379 Redis"));
    assert.ok(find("DKR-015", df("FROM alpine:3.20\nEXPOSE 5432/tcp\n")).controls.some((x) => x.framework === "CIS Docker Benchmark" && x.id === "5.8"));
  });
  test("DKR-016 Docker API / kubelet / RDP / Telnet EXPOSE", () => {
    pair("DKR-016", df("FROM docker:27-dind\nEXPOSE 2375\nUSER 1\n"), df("FROM alpine:3.20\nEXPOSE 8080 443\nUSER 1\n"));
    assert.ok(fires("DKR-016", df("FROM alpine:3.20\nEXPOSE 10250\n")));
  });
  test("DKR-017 pip cache only in the final stage", () => {
    pair("DKR-017", df("FROM python:3.12-slim\nRUN pip install flask==3.0.3\nUSER 1\n"), df("FROM python:3.12-slim\nRUN pip install --no-cache-dir flask==3.0.3\nUSER 1\n"));
    assert.ok(fires("DKR-017", df("FROM python:3.12-slim\nRUN python3 -m pip install -r req.txt\n")));
    assert.ok(!fires("DKR-017", df("FROM python:3.12 AS build\nRUN pip install flask==3.0.3\nFROM python:3.12-slim\nCOPY --from=build /x /x\n")));
    assert.ok(!fires("DKR-017", df("FROM python:3.12-slim\nENV PIP_NO_CACHE_DIR=1\nRUN pip install flask==3.0.3\n")));
    assert.ok(!fires("DKR-017", df("FROM python:3.12-slim\nRUN --mount=type=cache,target=/root/.cache/pip pip install flask==3.0.3\n")));
  });
  test("DKR-018 apt lists must be removed in the installing layer", () => {
    pair("DKR-018", df("FROM debian:12\nRUN apt-get update && apt-get install -y --no-install-recommends curl\nUSER 1\n"), df("FROM debian:12\nRUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*\nUSER 1\n"));
    assert.ok(fires("DKR-018", df("FROM debian:12\nRUN apt-get update && apt-get install -y curl\nRUN rm -rf /var/lib/apt/lists/*\n")));
  });
  test("DKR-019 COPY of the whole context, not from a stage", () => {
    pair("DKR-019", df("FROM node:22-slim\nCOPY . .\nUSER 1\n"), df("FROM node:22-slim\nCOPY src/ /app/src/\nUSER 1\n"));
    assert.ok(fires("DKR-019", df("FROM node:22-slim\nCOPY --chown=1:1 [\".\", \"/app\"]\n")));
    assert.ok(!fires("DKR-019", df("FROM node:22 AS b\nRUN true\nFROM node:22-slim\nCOPY --from=b . .\n")));
  });
  test("DKR-020 single-stage build that compiles", () => {
    pair("DKR-020", df("FROM golang:1.22\nCOPY main.go .\nRUN go build -o /app .\nUSER 1\n"), df("FROM golang:1.22 AS b\nRUN go build -o /app .\nFROM gcr.io/distroless/static:nonroot\nCOPY --from=b /app /app\n"));
    assert.ok(!fires("DKR-020", df("FROM nginx:1.27\nCOPY site/ /usr/share/nginx/html/\n")));
  });
  test("DKR-021 / K8S-037 runc Leaky Vessels workdir pattern", () => {
    pair("DKR-021", df("FROM alpine:3.20\nWORKDIR /proc/self/fd/7\nUSER 1\n"), df("FROM alpine:3.20\nWORKDIR /app\nUSER 1\n"));
    const f = find("DKR-021", df("FROM alpine:3.20\nWORKDIR /proc/self/fd/7\n"));
    assert.equal(f.line, 2);
    assert.ok(f.title.includes("CVE-2024-21626") && f.severity === "critical");
    pair("K8S-037", k8s(DEPLOY("          workingDir: /proc/self/fd/8\n")), k8s(DEPLOY("          workingDir: /app\n")));
  });
  test("escape CVE notes attach only to the matching condition", () => {
    const sc = (caps) => k8s(DEPLOY("          securityContext:\n            capabilities:\n              add: [" + caps + "]\n"));
    assert.ok(find("K8S-010", sc("\"SYS_ADMIN\"")).description.includes("CVE-2022-0492"));
    assert.ok(!find("K8S-010", sc("\"NET_ADMIN\"")).description.includes("CVE-"));
    const cm = (opt) => compose("services:\n  a:\n    image: a:1\n    security_opt:\n      - " + opt + "\n");
    assert.ok(find("CMP-008", cm("seccomp:unconfined")).description.includes("CVE-2022-0185"));
    assert.ok(!find("CMP-008", cm("apparmor:unconfined")).description.includes("CVE-"));
  });
  test("CIS Docker ids on compose runtime rules", () => {
    const cis = (id, files) => find(id, files).controls.filter((x) => x.framework === "CIS Docker Benchmark").map((x) => x.id);
    assert.deepEqual(cis("CMP-001", compose("services:\n  a:\n    image: a:1\n    privileged: true\n")), ["5.4"]);
    assert.deepEqual(cis("CMP-002", compose("services:\n  a:\n    image: a:1\n    network_mode: host\n")), ["5.9"]);
    assert.deepEqual(cis("CMP-007", compose("services:\n  db:\n    image: mysql:8\n    ports:\n      - \"3306:3306\"\n")), ["5.13"]);
  });
});

group("iacscan: IAM privilege-escalation paths", () => {
  const pol = (stmts) => tf('resource "aws_iam_policy" "p" {\n  policy = ' + JSON.stringify(JSON.stringify({ Version: "2012-10-17", Statement: stmts })) + "\n}\n");
  const allow = (Action, Resource = "*", extra = {}) => ({ Effect: "Allow", Action, Resource, ...extra });
  const find = (id, files) => analyze(files).findings.find((x) => x.ruleId === id);
  test("every path has a severity, concrete actions and an explanation", () => {
    assert.ok(IAM_PRIVESC.length >= 20);
    for (const p of IAM_PRIVESC) {
      assert.ok(["critical", "high", "medium"].includes(p.sev), p.name);
      assert.ok(p.actions.length && p.actions.every((a) => /^[a-z0-9-]+:[A-Za-z]+$/.test(a)), p.name);
      assert.ok(p.why.length > 20, p.name);
    }
  });
  test("AWS-IAM-011 single-action and cross-statement combos", () => {
    pair("AWS-IAM-011", pol([allow("iam:AttachUserPolicy")]), pol([allow("iam:ListPolicies")]));
    const f = find("AWS-IAM-011", pol([allow("iam:PassRole"), allow(["ec2:RunInstances", "ec2:DescribeInstances"])]));
    assert.ok(f && f.description.includes("PassRole to EC2") && f.confidence === "confirmed");
    assert.ok(!fires("AWS-IAM-011", pol([allow("iam:PassRole")])), "PassRole alone is not the EC2 path");
  });
  test("wildcards match, Deny removes, full admin is left to AWS-IAM-001", () => {
    assert.ok(fires("AWS-IAM-011", pol([allow("iam:Attach*")])));
    assert.ok(fires("AWS-IAM-011", pol([allow("IAM:PutRole?olicy")])));
    assert.ok(!fires("AWS-IAM-011", pol([allow("iam:*"), { Effect: "Deny", Action: ["iam:Attach*", "iam:Put*", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:PassRole"], Resource: "*" }])));
    const admin = ids(pol([allow("*")]));
    assert.ok(admin.includes("AWS-IAM-001") && !admin.includes("AWS-IAM-011"));
  });
  test("scoped resources or conditions downgrade to review", () => {
    assert.equal(find("AWS-IAM-012", pol([allow("iam:CreateAccessKey", "arn:aws:iam::111122223333:user/ops")])).confidence, "review");
    assert.equal(find("AWS-IAM-012", pol([allow("iam:CreateAccessKey", "*", { Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } })])).confidence, "review");
  });
  test("AWS-IAM-012 / 013 severities; resource policies are ignored", () => {
    assert.equal(find("AWS-IAM-012", pol([allow("ssm:StartSession")])).severity, "high");
    assert.equal(find("AWS-IAM-013", pol([allow(["iam:PassRole", "codestar:CreateProject"], ["arn:aws:iam::1:role/x"])])).severity, "medium");
    assert.ok(!fires("AWS-IAM-012", tf('resource "aws_s3_bucket_policy" "b" {\n  policy = ' + JSON.stringify(JSON.stringify({ Statement: [allow("iam:CreateAccessKey")] })) + "\n}\n")));
    assert.deepEqual(privescPaths([]), []);
  });
});
