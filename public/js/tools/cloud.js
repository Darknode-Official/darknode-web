// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Cloud & Container Security mini-tools: parsers, linters, explainers and builders
// for AWS / GCP / Azure, Kubernetes, Docker/OCI and Terraform. All pure client-side,
// deterministic, no network. For reviewing and hardening systems you operate or are
// authorised to test. See _schema.md.

const S = (v) => (v == null ? "" : String(v));
const lines = (a) => a.filter((x) => x != null).join("\n");

// ---- IPv4 helpers ----
const ipToInt = (ip) => {
  const p = String(ip).trim().split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const o of p) { if (!/^\d{1,3}$/.test(o)) return null; const x = Number(o); if (x > 255) return null; n = n * 256 + x; }
  return n >>> 0;
};
const intToIp = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
const parseCidr = (c) => {
  const m = String(c).trim().match(/^([0-9.]+)\/(\d{1,2})$/);
  if (!m) return null;
  const base = ipToInt(m[1]); const bits = Number(m[2]);
  if (base == null || bits > 32) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const network = (base & mask) >>> 0;
  return { base, bits, mask, network, bcast: (network | (~mask >>> 0)) >>> 0, size: 2 ** (32 - bits) };
};

// ---- query-string parse (no DOM) ----
const dec = (s) => { try { return decodeURIComponent(s.replace(/\+/g, " ")); } catch (e) { return s; } };
const qparse = (url) => {
  const out = {}; const i = String(url).indexOf("?"); if (i < 0) return out;
  let q = String(url).slice(i + 1); const h = q.indexOf("#"); if (h >= 0) q = q.slice(0, h);
  for (const kv of q.split("&")) { if (!kv) continue; const j = kv.indexOf("="); const k = dec(j < 0 ? kv : kv.slice(0, j)); out[k] = j < 0 ? "" : dec(kv.slice(j + 1)); }
  return out;
};

// ---- base32 decode to raw bytes (RFC 4648, for AWS key IDs) ----
const B32A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function b32bytes(s) {
  const t = String(s).toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  let bits = 0, val = 0; const out = [];
  for (const c of t) { const idx = B32A.indexOf(c); if (idx < 0) return null; val = (val << 5) | idx; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  return out;
}

// ---- shared data: dangerous ports exposed to the internet ----
const RISKY_PORTS = {
  22: "SSH", 23: "Telnet (cleartext)", 135: "MSRPC", 139: "NetBIOS", 445: "SMB",
  1433: "MSSQL", 1521: "Oracle DB", 2375: "Docker API (unauthenticated)", 2376: "Docker API (TLS)",
  2379: "etcd client", 2380: "etcd peer", 3306: "MySQL/MariaDB", 3389: "RDP", 4444: "Metasploit/handler",
  5432: "PostgreSQL", 5601: "Kibana", 5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes API",
  8080: "HTTP alt/proxy", 9000: "various admin", 9200: "Elasticsearch", 9300: "Elasticsearch transport",
  10250: "kubelet API", 10255: "kubelet read-only", 11211: "Memcached", 15672: "RabbitMQ mgmt",
  27017: "MongoDB", 5000: "various/registry", 8443: "HTTPS alt",
};

export const TOOLS = [
  // ======================= AWS: ARN / keys =======================
  { id: "cl-arn-parse", name: "AWS ARN Parser", cat: "cloud", desc: "Split an Amazon Resource Name into partition, service, region, account and resource parts.", tags: ["aws", "arn", "parse"],
    inputs: [{ k: "arn", label: "ARN", type: "text", placeholder: "arn:aws:s3:::my-bucket/path/key" }],
    run(v) {
      const arn = S(v.arn).trim();
      if (!arn) return "";
      const p = arn.split(":");
      if (p.length < 6 || p[0] !== "arn") return { error: "Not an ARN (expected arn:partition:service:region:account:resource)." };
      const [, partition, service, region, account] = p;
      const resource = p.slice(5).join(":");
      let resType = "", resId = resource;
      const sep = resource.search(/[:/]/);
      if (sep >= 0) { resType = resource.slice(0, sep); resId = resource.slice(sep + 1); }
      return lines([
        `partition  ${partition || "(empty)"}`,
        `service    ${service || "(empty)"}`,
        `region     ${region || "(empty / global)"}`,
        `account    ${account || "(empty / not applicable)"}`,
        `resource   ${resource}`,
        resType ? `  type     ${resType}` : null,
        resType ? `  id       ${resId}` : null,
      ]);
    } },

  { id: "cl-arn-build", name: "AWS ARN Builder", cat: "cloud", desc: "Assemble a valid ARN from its parts (partition, service, region, account, resource).", tags: ["aws", "arn", "build"],
    inputs: [
      { k: "partition", label: "Partition", type: "select", opts: ["aws", "aws-cn", "aws-us-gov"], value: "aws" },
      { k: "service", label: "Service", type: "text", placeholder: "s3, iam, ec2, lambda..." },
      { k: "region", label: "Region (blank for global)", type: "text", placeholder: "us-east-1" },
      { k: "account", label: "Account ID (blank if N/A)", type: "text", placeholder: "123456789012" },
      { k: "resource", label: "Resource", type: "text", placeholder: "my-bucket/key or role/Admin" },
    ],
    run(v) {
      const service = S(v.service).trim();
      if (!service) return "";
      const resource = S(v.resource).trim();
      if (!resource) return { error: "Resource is required." };
      return `arn:${S(v.partition).trim() || "aws"}:${service}:${S(v.region).trim()}:${S(v.account).trim()}:${resource}`;
    } },

  { id: "cl-akia-decode", name: "AWS Access Key ID Decoder", cat: "cloud", desc: "Identify the type of an AWS access key ID from its prefix and derive the owning account ID (documented offline derivation).", tags: ["aws", "akia", "asia", "access key", "account id"],
    inputs: [{ k: "key", label: "Access Key ID", type: "text", placeholder: "AKIAIOSFODNN7EXAMPLE" }],
    run(v) {
      const key = S(v.key).trim();
      if (!key) return "";
      if (!/^[A-Z2-7]{4}[A-Z2-7]+$/.test(key)) return { error: "Expected an AWS key ID: uppercase A-Z and digits 2-7, e.g. AKIA..." };
      const PFX = { ABIA: "STS service bearer token", ACCA: "Context-specific credential", AGPA: "IAM user group", AIDA: "IAM user", AIPA: "EC2 instance profile", AKIA: "Long-term access key (IAM user or root)", ANPA: "Managed policy", ANVA: "Managed policy version", APKA: "Public key (SSH / CodeCommit)", AROA: "IAM role", ASCA: "Certificate", ASIA: "Temporary access key (STS session)" };
      const prefix = key.slice(0, 4);
      const out = [`Key ID   ${key}`, `Prefix   ${prefix} — ${PFX[prefix] || "unknown / not a recognised AWS prefix"}`, `Length   ${key.length}`];
      if (key.length === 20) {
        const by = b32bytes(key.slice(4));
        if (by && by.length >= 6) {
          let z = 0n; for (let i = 0; i < 6; i++) z = (z << 8n) | BigInt(by[i]);
          const acct = (z & 0x7fffffffff80n) >> 7n;
          out.push(`Account  ${acct.toString().padStart(12, "0")}`);
          out.push(`(Account ID is encoded in the key material; derived locally, no API call.)`);
        }
      } else {
        out.push("Account-ID derivation applies to 20-character key IDs (AKIA/ASIA) only.");
      }
      if (prefix === "ASIA") out.push("Note: ASIA keys are temporary and require a matching session token.");
      return lines(out);
    } },

  { id: "cl-aws-partition-ref", name: "AWS Partition Reference", cat: "cloud", desc: "Reference of AWS partitions used in ARNs and their region/DNS naming.", tags: ["aws", "partition", "arn", "govcloud", "china"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "gov, china..." }],
    run(v) {
      const rows = [
        ["aws", "Standard (commercial) partition — most regions, *.amazonaws.com"],
        ["aws-cn", "China partition (Beijing cn-north-1, Ningxia cn-northwest-1) — *.amazonaws.com.cn"],
        ["aws-us-gov", "AWS GovCloud (US) partition — us-gov-east-1, us-gov-west-1"],
      ];
      const q = S(v.q).toLowerCase().trim();
      const m = rows.filter(([a, b]) => !q || a.includes(q) || b.toLowerCase().includes(q));
      return m.length ? m.map(([a, b]) => `${a.padEnd(11)} ${b}`).join("\n") : "No matches.";
    } },

  { id: "cl-aws-region-ref", name: "AWS Region Code Reference", cat: "cloud", desc: "Look up an AWS region code and its geographic name, or search by location.", tags: ["aws", "region", "reference"],
    inputs: [{ k: "q", label: "Filter (code or place, blank = all)", type: "text", placeholder: "eu, tokyo, us-east..." }],
    run(v) {
      const R = [
        ["us-east-1", "US East (N. Virginia)"], ["us-east-2", "US East (Ohio)"], ["us-west-1", "US West (N. California)"], ["us-west-2", "US West (Oregon)"],
        ["ca-central-1", "Canada (Central)"], ["ca-west-1", "Canada West (Calgary)"], ["sa-east-1", "South America (Sao Paulo)"],
        ["eu-west-1", "Europe (Ireland)"], ["eu-west-2", "Europe (London)"], ["eu-west-3", "Europe (Paris)"], ["eu-central-1", "Europe (Frankfurt)"], ["eu-central-2", "Europe (Zurich)"],
        ["eu-north-1", "Europe (Stockholm)"], ["eu-south-1", "Europe (Milan)"], ["eu-south-2", "Europe (Spain)"],
        ["ap-east-1", "Asia Pacific (Hong Kong)"], ["ap-south-1", "Asia Pacific (Mumbai)"], ["ap-south-2", "Asia Pacific (Hyderabad)"],
        ["ap-northeast-1", "Asia Pacific (Tokyo)"], ["ap-northeast-2", "Asia Pacific (Seoul)"], ["ap-northeast-3", "Asia Pacific (Osaka)"],
        ["ap-southeast-1", "Asia Pacific (Singapore)"], ["ap-southeast-2", "Asia Pacific (Sydney)"], ["ap-southeast-3", "Asia Pacific (Jakarta)"], ["ap-southeast-4", "Asia Pacific (Melbourne)"],
        ["af-south-1", "Africa (Cape Town)"], ["me-south-1", "Middle East (Bahrain)"], ["me-central-1", "Middle East (UAE)"], ["il-central-1", "Israel (Tel Aviv)"],
        ["us-gov-east-1", "AWS GovCloud (US-East)"], ["us-gov-west-1", "AWS GovCloud (US-West)"], ["cn-north-1", "China (Beijing)"], ["cn-northwest-1", "China (Ningxia)"],
      ];
      const q = S(v.q).toLowerCase().trim();
      const m = R.filter(([a, b]) => !q || a.includes(q) || b.toLowerCase().includes(q));
      return m.length ? m.map(([a, b]) => `${a.padEnd(16)} ${b}`).join("\n") : "No matching region.";
    } },

  // ======================= AWS: IAM policy =======================
  { id: "cl-iam-policy-lint", name: "AWS IAM Policy Linter", cat: "cloud", desc: "Scan an IAM policy JSON for overly-broad grants: Action/Resource wildcards, NotAction/NotResource with Allow, public principals and missing conditions.", tags: ["aws", "iam", "policy", "lint", "least-privilege"],
    inputs: [{ k: "json", label: "Policy JSON", type: "textarea", rows: 10, placeholder: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' }],
    run(v) {
      const txt = S(v.json).trim();
      if (!txt) return "";
      let pol; try { pol = JSON.parse(txt); } catch (e) { return { error: "Not valid JSON." }; }
      let stmts = pol.Statement; if (!stmts) return { error: "No Statement found." };
      if (!Array.isArray(stmts)) stmts = [stmts];
      const asArr = (x) => (x == null ? [] : Array.isArray(x) ? x : [x]);
      const findings = [];
      stmts.forEach((st, i) => {
        const sid = st.Sid ? `"${st.Sid}"` : `#${i + 1}`;
        const allow = st.Effect === "Allow";
        const add = (sev, msg) => findings.push(`[${sev}] Statement ${sid}: ${msg}`);
        const actions = asArr(st.Action).map(String);
        const resources = asArr(st.Resource).map(String);
        if (allow && actions.includes("*")) add("HIGH", 'Action "*" with Allow grants every action (admin).');
        actions.forEach((a) => { if (a !== "*" && a.endsWith(":*")) add("MED", `Action "${a}" allows every action in that service.`); });
        if (allow && (actions.includes("iam:*") || actions.some((a) => /^iam:(Create|Put|Attach|Update|PassRole)/i.test(a)))) add("HIGH", "Grants IAM write/PassRole — can lead to privilege escalation.");
        if (allow && resources.includes("*") && !actions.includes("*")) add("MED", 'Resource "*" with Allow — not scoped to specific resources.');
        if (allow && st.NotAction) add("HIGH", "Allow + NotAction grants everything EXCEPT the listed actions (very broad).");
        if (allow && st.NotResource) add("MED", "Allow + NotResource applies to everything EXCEPT the listed resources.");
        if (st.Principal) {
          const pr = st.Principal;
          const pub = pr === "*" || (pr && (pr.AWS === "*" || (Array.isArray(pr.AWS) && pr.AWS.includes("*"))));
          if (allow && pub && !st.Condition) add("HIGH", 'Principal "*" with Allow and no Condition — resource is public.');
          else if (allow && pub) add("MED", 'Principal "*" (public), restricted only by Condition — verify the condition is sufficient.');
        }
      });
      if (!findings.length) return "No obvious over-broad grants found. (This is a heuristic lint, not a full authorization review.)";
      return `${findings.length} finding(s):\n\n` + findings.join("\n");
    } },

  { id: "cl-iam-policy-explain", name: "AWS IAM Policy Explainer", cat: "cloud", desc: "Describe each statement of an IAM policy in plain English: who, allowed or denied, which actions, which resources and under what conditions.", tags: ["aws", "iam", "policy", "explain"],
    inputs: [{ k: "json", label: "Policy JSON", type: "textarea", rows: 10, placeholder: '{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::b/*"}]}' }],
    run(v) {
      const txt = S(v.json).trim();
      if (!txt) return "";
      let pol; try { pol = JSON.parse(txt); } catch (e) { return { error: "Not valid JSON." }; }
      let stmts = pol.Statement; if (!stmts) return { error: "No Statement found." };
      if (!Array.isArray(stmts)) stmts = [stmts];
      const asArr = (x) => (x == null ? [] : Array.isArray(x) ? x : [x]);
      const out = [];
      stmts.forEach((st, i) => {
        const parts = [`Statement ${st.Sid ? '"' + st.Sid + '"' : "#" + (i + 1)}:`];
        const eff = st.Effect === "Deny" ? "DENIES" : "ALLOWS";
        if (st.Principal) parts.push(`  Principal: ${typeof st.Principal === "string" ? st.Principal : JSON.stringify(st.Principal)}`);
        const actKey = st.NotAction ? "every action EXCEPT" : "";
        const acts = asArr(st.Action).concat(asArr(st.NotAction)).map(String);
        parts.push(`  ${eff} ${actKey} ${acts.join(", ") || "(no actions)"}`.replace(/\s+/g, " "));
        const resKey = st.NotResource ? "every resource EXCEPT" : "on";
        const res = asArr(st.Resource).concat(asArr(st.NotResource)).map(String);
        parts.push(`  ${resKey} ${res.join(", ") || "(no resource specified)"}`);
        if (st.Condition) parts.push(`  only when conditions met: ${Object.keys(st.Condition).join(", ")}`);
        out.push(parts.join("\n"));
      });
      return out.join("\n\n");
    } },

  { id: "cl-iam-policy-build", name: "AWS IAM Policy Builder", cat: "cloud", desc: "Generate a least-privilege IAM policy statement from a service, actions, resource ARN and optional condition.", tags: ["aws", "iam", "policy", "build", "least-privilege"],
    inputs: [
      { k: "effect", label: "Effect", type: "select", opts: ["Allow", "Deny"], value: "Allow" },
      { k: "actions", label: "Actions (comma/space separated)", type: "text", placeholder: "s3:GetObject s3:PutObject" },
      { k: "resource", label: "Resource ARN(s)", type: "text", placeholder: "arn:aws:s3:::my-bucket/*" },
      { k: "sid", label: "Sid (optional)", type: "text", placeholder: "AllowBucketRW" },
      { k: "condKey", label: "Condition key (optional)", type: "text", placeholder: "aws:SourceIp" },
      { k: "condOp", label: "Condition operator", type: "select", opts: ["IpAddress", "StringEquals", "Bool", "ArnLike", "DateLessThan"], value: "IpAddress" },
      { k: "condVal", label: "Condition value (optional)", type: "text", placeholder: "198.51.100.0/24" },
    ],
    run(v) {
      const actions = S(v.actions).split(/[\s,]+/).filter(Boolean);
      const res = S(v.resource).split(/[\s,]+/).filter(Boolean);
      if (!actions.length) return "";
      if (!res.length) return { error: "At least one resource ARN is required (use * only when intentional)." };
      const st = { Effect: S(v.effect) || "Allow", Action: actions.length === 1 ? actions[0] : actions, Resource: res.length === 1 ? res[0] : res };
      if (S(v.sid).trim()) st.Sid = S(v.sid).trim();
      if (S(v.condKey).trim() && S(v.condVal).trim()) st.Condition = { [v.condOp]: { [S(v.condKey).trim()]: S(v.condVal).trim() } };
      const doc = { Version: "2012-10-17", Statement: [st] };
      const warn = actions.includes("*") || res.includes("*") ? "\n\n// note: contains a wildcard (*) — confirm this is intended." : "";
      return JSON.stringify(doc, null, 2) + warn;
    } },

  { id: "cl-iam-condition-keys", name: "AWS IAM Condition Key Reference", cat: "cloud", desc: "Reference of common global IAM condition keys used to tighten policies (source IP, MFA, org, TLS, region).", tags: ["aws", "iam", "condition", "reference"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "mfa, ip, org..." }],
    run(v) {
      const K = [
        ["aws:SourceIp", "Caller's public IP; pair with IpAddress operator to restrict by CIDR"],
        ["aws:SecureTransport", "Bool — true when the request used TLS/HTTPS; deny when false"],
        ["aws:MultiFactorAuthPresent", "Bool — true when the session was authenticated with MFA"],
        ["aws:MultiFactorAuthAge", "Seconds since MFA; use with NumericLessThan for recent-MFA checks"],
        ["aws:PrincipalOrgID", "Restrict to principals in a specific AWS Organizations org"],
        ["aws:PrincipalArn", "Exact ARN of the calling principal"],
        ["aws:RequestedRegion", "Region the request targets; restrict services to approved regions"],
        ["aws:SourceArn", "ARN of the resource making a service-to-service call (confused-deputy)"],
        ["aws:SourceAccount", "Account ID of the calling service (confused-deputy defence)"],
        ["aws:ViaAWSService", "Bool — true when the request was made by an AWS service on your behalf"],
        ["aws:userid", "Unique ID of the principal"],
        ["aws:PrincipalTag/<k>", "Value of a tag on the calling principal (ABAC)"],
        ["aws:RequestTag/<k>", "Tag being set in the request (ABAC on create)"],
        ["aws:TagKeys", "The set of tag keys in the request"],
        ["aws:CurrentTime", "Request timestamp; use with DateLessThan/DateGreaterThan"],
      ];
      const q = S(v.q).toLowerCase().trim();
      const m = K.filter(([a, b]) => !q || a.toLowerCase().includes(q) || b.toLowerCase().includes(q));
      return m.length ? m.map(([a, b]) => `${a}\n    ${b}`).join("\n") : "No matches.";
    } },

  { id: "cl-managed-policy-risk", name: "AWS Risky Managed Policy Reference", cat: "cloud", desc: "Reference of broad AWS-managed policies that grant wide access and should be attached sparingly.", tags: ["aws", "iam", "managed policy", "privilege"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "admin, iam..." }],
    run(v) {
      const P = [
        ["AdministratorAccess", "Effectively Action:* on Resource:* — full control of the account."],
        ["PowerUserAccess", "Full access to all services EXCEPT IAM and Organizations management."],
        ["IAMFullAccess", "Full IAM control — can create users/roles/policies (privilege escalation path)."],
        ["AdministratorAccess-* (service variants)", "Scoped admin for a service; still very broad within it."],
      ];
      const q = S(v.q).toLowerCase().trim();
      const m = P.filter(([a, b]) => !q || a.toLowerCase().includes(q) || b.toLowerCase().includes(q));
      return (m.length ? m.map(([a, b]) => `${a}\n    ${b}`).join("\n") : "No matches.") + "\n\nPrefer scoped, least-privilege policies; grant these only to break-glass or trusted admin roles.";
    } },

  { id: "cl-sts-assume-role", name: "aws sts assume-role Builder", cat: "cloud", desc: "Build an aws sts assume-role CLI command with role ARN, session name, optional external ID, MFA and duration.", tags: ["aws", "sts", "assume-role", "cli", "builder"],
    inputs: [
      { k: "arn", label: "Role ARN", type: "text", placeholder: "arn:aws:iam::123456789012:role/Deploy" },
      { k: "session", label: "Session name", type: "text", value: "cli-session" },
      { k: "external", label: "External ID (optional)", type: "text", placeholder: "unique-id" },
      { k: "mfa", label: "MFA serial (optional)", type: "text", placeholder: "arn:aws:iam::123456789012:mfa/alice" },
      { k: "token", label: "MFA token code (optional)", type: "text", placeholder: "123456" },
      { k: "duration", label: "Duration (seconds)", type: "text", value: "3600" },
    ],
    run(v) {
      const arn = S(v.arn).trim();
      if (!arn) return "";
      if (!/^arn:aws[\w-]*:iam::\d{12}:role\//.test(arn)) return { error: "Expected an IAM role ARN like arn:aws:iam::123456789012:role/Name." };
      const parts = ["aws sts assume-role", `  --role-arn ${arn}`, `  --role-session-name ${S(v.session).trim() || "cli-session"}`];
      if (S(v.external).trim()) parts.push(`  --external-id ${S(v.external).trim()}`);
      if (S(v.mfa).trim() && S(v.token).trim()) parts.push(`  --serial-number ${S(v.mfa).trim()}`, `  --token-code ${S(v.token).trim()}`);
      if (S(v.duration).trim()) parts.push(`  --duration-seconds ${S(v.duration).trim()}`);
      return parts.join(" \\\n");
    } },

  // ======================= AWS: S3 =======================
  { id: "cl-s3-bucket-policy-explain", name: "S3 Bucket Policy Explainer", cat: "cloud", desc: "Explain an S3 bucket policy and flag statements that make the bucket or its objects publicly accessible.", tags: ["aws", "s3", "bucket policy", "public"],
    inputs: [{ k: "json", label: "Bucket policy JSON", type: "textarea", rows: 10, placeholder: '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}' }],
    run(v) {
      const txt = S(v.json).trim();
      if (!txt) return "";
      let pol; try { pol = JSON.parse(txt); } catch (e) { return { error: "Not valid JSON." }; }
      let stmts = pol.Statement; if (!stmts) return { error: "No Statement found." };
      if (!Array.isArray(stmts)) stmts = [stmts];
      const asArr = (x) => (x == null ? [] : Array.isArray(x) ? x : [x]);
      const out = [];
      stmts.forEach((st, i) => {
        const sid = st.Sid ? '"' + st.Sid + '"' : "#" + (i + 1);
        const pr = st.Principal;
        const pub = pr === "*" || (pr && (pr.AWS === "*" || (Array.isArray(pr.AWS) && pr.AWS.includes("*"))));
        const actions = asArr(st.Action).map(String).join(", ");
        const res = asArr(st.Resource).map(String).join(", ");
        const flag = st.Effect === "Allow" && pub ? (st.Condition ? " [PUBLIC — restricted by Condition, verify]" : " [PUBLIC — anyone can call these actions]") : "";
        out.push(`Statement ${sid}${flag}\n  ${st.Effect} ${actions || "(no action)"} for principal ${typeof pr === "string" ? pr : JSON.stringify(pr)}\n  on ${res}${st.Condition ? "\n  condition: " + Object.keys(st.Condition).join(", ") : ""}`);
      });
      return out.join("\n\n");
    } },

  { id: "cl-s3-policy-build", name: "S3 Bucket Policy Builder", cat: "cloud", desc: "Generate an S3 bucket policy that denies non-TLS access or grants a specific principal scoped access to a bucket.", tags: ["aws", "s3", "bucket policy", "build", "tls"],
    inputs: [
      { k: "bucket", label: "Bucket name", type: "text", placeholder: "my-bucket" },
      { k: "template", label: "Template", type: "select", opts: ["Deny insecure (non-TLS) transport", "Grant principal read/write"], value: "Deny insecure (non-TLS) transport" },
      { k: "principal", label: "Principal ARN (for grant template)", type: "text", placeholder: "arn:aws:iam::123456789012:role/App" },
    ],
    run(v) {
      const b = S(v.bucket).trim();
      if (!b) return "";
      const arn = `arn:aws:s3:::${b}`;
      let doc;
      if (v.template === "Grant principal read/write") {
        const pr = S(v.principal).trim();
        if (!pr) return { error: "Principal ARN is required for the grant template." };
        doc = { Version: "2012-10-17", Statement: [{ Sid: "ScopedAccess", Effect: "Allow", Principal: { AWS: pr }, Action: ["s3:GetObject", "s3:PutObject", "s3:ListBucket"], Resource: [arn, `${arn}/*`] }] };
      } else {
        doc = { Version: "2012-10-17", Statement: [{ Sid: "DenyInsecureTransport", Effect: "Deny", Principal: "*", Action: "s3:*", Resource: [arn, `${arn}/*`], Condition: { Bool: { "aws:SecureTransport": "false" } } }] };
      }
      return JSON.stringify(doc, null, 2);
    } },

  { id: "cl-s3-canned-acl", name: "S3 Canned ACL Reference", cat: "cloud", desc: "Explain each S3 canned ACL and highlight the ones that make objects or buckets public.", tags: ["aws", "s3", "acl", "reference", "public"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "public, owner..." }],
    run(v) {
      const A = [
        ["private", "Owner gets FULL_CONTROL. No public access. (default)"],
        ["public-read", "Owner FULL_CONTROL; everyone (AllUsers) can READ. PUBLIC."],
        ["public-read-write", "Everyone can READ and WRITE. Dangerous; almost never appropriate. PUBLIC."],
        ["aws-exec-read", "Owner FULL_CONTROL; Amazon EC2 gets READ for AMI bundles."],
        ["authenticated-read", "Owner FULL_CONTROL; any authenticated AWS user can READ. Broadly public."],
        ["bucket-owner-read", "Object owner FULL_CONTROL; bucket owner can READ the object."],
        ["bucket-owner-full-control", "Object and bucket owner both get FULL_CONTROL (recommended for cross-account uploads)."],
        ["log-delivery-write", "Log Delivery group can WRITE/READ_ACP — used for S3 server access logging buckets."],
      ];
      const q = S(v.q).toLowerCase().trim();
      const m = A.filter(([a, b]) => !q || a.includes(q) || b.toLowerCase().includes(q));
      return m.length ? m.map(([a, b]) => `${a}\n    ${b}`).join("\n") : "No matches.";
    } },

  { id: "cl-s3-url-parse", name: "S3 URL Parser", cat: "cloud", desc: "Parse any S3 URL form (s3://, virtual-hosted, path-style) into bucket, key and region.", tags: ["aws", "s3", "url", "parse"],
    inputs: [{ k: "url", label: "S3 URL", type: "text", placeholder: "https://my-bucket.s3.us-east-1.amazonaws.com/path/key.txt" }],
    run(v) {
      const u = S(v.url).trim();
      if (!u) return "";
      let m;
      if ((m = u.match(/^s3:\/\/([^/]+)\/?(.*)$/i))) return lines([`scheme     s3:// (CLI / SDK URI)`, `bucket     ${m[1]}`, `key        ${m[2] || "(none)"}`]);
      if ((m = u.match(/^https?:\/\/([^.]+)\.s3[.-]([a-z0-9-]+)\.amazonaws\.com\/?(.*)$/i))) return lines([`style      virtual-hosted`, `bucket     ${m[1]}`, `region     ${m[2]}`, `key        ${(m[3] || "").split("?")[0] || "(none)"}`]);
      if ((m = u.match(/^https?:\/\/([^.]+)\.s3\.amazonaws\.com\/?(.*)$/i))) return lines([`style      virtual-hosted (global/us-east-1)`, `bucket     ${m[1]}`, `key        ${(m[2] || "").split("?")[0] || "(none)"}`]);
      if ((m = u.match(/^https?:\/\/s3[.-]([a-z0-9-]+)\.amazonaws\.com\/([^/]+)\/?(.*)$/i))) return lines([`style      path-style`, `region     ${m[1]}`, `bucket     ${m[2]}`, `key        ${(m[3] || "").split("?")[0] || "(none)"}`]);
      if ((m = u.match(/^https?:\/\/s3\.amazonaws\.com\/([^/]+)\/?(.*)$/i))) return lines([`style      path-style (global/us-east-1)`, `bucket     ${m[1]}`, `key        ${(m[2] || "").split("?")[0] || "(none)"}`]);
      return { error: "Did not recognise this as an S3 URL." };
    } },

  { id: "cl-s3-url-build", name: "S3 URL Builder", cat: "cloud", desc: "Build the s3://, virtual-hosted and path-style URLs for a bucket, key and region.", tags: ["aws", "s3", "url", "build"],
    inputs: [
      { k: "bucket", label: "Bucket", type: "text", placeholder: "my-bucket" },
      { k: "key", label: "Key / path", type: "text", placeholder: "path/key.txt" },
      { k: "region", label: "Region", type: "text", value: "us-east-1" },
    ],
    run(v) {
      const b = S(v.bucket).trim();
      if (!b) return "";
      const key = S(v.key).trim().replace(/^\//, "");
      const region = S(v.region).trim() || "us-east-1";
      const k = key ? "/" + key : "";
      return lines([
        `s3 URI          s3://${b}${k}`,
        `virtual-hosted  https://${b}.s3.${region}.amazonaws.com${k}`,
        `path-style      https://s3.${region}.amazonaws.com/${b}${k}`,
      ]);
    } },

  { id: "cl-s3-name-validate", name: "S3 Bucket Name Validator", cat: "cloud", desc: "Check a bucket name against AWS S3 general-purpose bucket naming rules.", tags: ["aws", "s3", "bucket", "naming", "validate"],
    inputs: [{ k: "name", label: "Bucket name", type: "text", placeholder: "my-bucket-name" }],
    run(v) {
      const n = S(v.name).trim();
      if (!n) return "";
      const errs = [];
      if (n.length < 3 || n.length > 63) errs.push("must be 3-63 characters");
      if (!/^[a-z0-9.-]+$/.test(n)) errs.push("only lowercase letters, digits, hyphens and dots allowed");
      if (/[A-Z]/.test(n)) errs.push("no uppercase letters");
      if (/_/.test(n)) errs.push("underscores are not allowed");
      if (!/^[a-z0-9]/.test(n) || !/[a-z0-9]$/.test(n)) errs.push("must start and end with a letter or digit");
      if (/\.\./.test(n)) errs.push("cannot contain two adjacent dots");
      if (/^\d+\.\d+\.\d+\.\d+$/.test(n)) errs.push("must not be formatted as an IP address");
      if (/^xn--/.test(n)) errs.push("must not start with the prefix xn--");
      if (/^sthree-/.test(n)) errs.push("must not start with the reserved prefix sthree-");
      if (/-s3alias$/.test(n) || /--ol-s3$/.test(n)) errs.push("must not end with -s3alias or --ol-s3 (reserved)");
      return errs.length ? `INVALID: ${n}\n- ` + errs.join("\n- ") : `VALID: ${n} satisfies the S3 general-purpose bucket naming rules.`;
    } },

  { id: "cl-s3-presigned-explain", name: "S3 Presigned URL Explainer", cat: "cloud", desc: "Decode the SigV4 query parameters of a presigned S3 URL: key ID, scope, signed headers, and when it expires.", tags: ["aws", "s3", "presigned", "sigv4", "expiry"],
    inputs: [{ k: "url", label: "Presigned URL", type: "textarea", rows: 4, placeholder: "https://b.s3.amazonaws.com/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=..." }],
    run(v) {
      const u = S(v.url).trim();
      if (!u) return "";
      const q = qparse(u);
      if (!q["X-Amz-Signature"] && !q["X-Amz-Algorithm"]) return { error: "No SigV4 query parameters found (expected X-Amz-* params)." };
      const out = [];
      if (q["X-Amz-Algorithm"]) out.push(`algorithm      ${q["X-Amz-Algorithm"]}`);
      if (q["X-Amz-Credential"]) {
        const c = q["X-Amz-Credential"].split("/");
        out.push(`credential     ${q["X-Amz-Credential"]}`);
        if (c.length === 5) out.push(`  access key   ${c[0]}`, `  scope date   ${c[1]}`, `  region       ${c[2]}`, `  service      ${c[3]}`);
      }
      if (q["X-Amz-SignedHeaders"]) out.push(`signed headers ${q["X-Amz-SignedHeaders"]}`);
      if (q["X-Amz-Security-Token"]) out.push(`session token  present (temporary STS credentials)`);
      if (q["X-Amz-Date"] && q["X-Amz-Expires"]) {
        const d = q["X-Amz-Date"].match(/^(\d{4})(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)Z$/);
        if (d) {
          const start = Date.UTC(+d[1], +d[2] - 1, +d[3], +d[4], +d[5], +d[6]);
          const secs = parseInt(q["X-Amz-Expires"], 10);
          const exp = new Date(start + secs * 1000);
          out.push(`signed at      ${new Date(start).toISOString()}`);
          out.push(`expires in     ${secs} s (${(secs / 3600).toFixed(2)} h)`);
          out.push(`expires at     ${exp.toISOString()}`);
          if (secs > 86400) out.push(`  WARNING: validity exceeds 24h — long-lived presigned URLs are a leak risk.`);
        }
      }
      if (q["X-Amz-Signature"]) out.push(`signature      ${q["X-Amz-Signature"].slice(0, 16)}... (${q["X-Amz-Signature"].length} hex chars)`);
      return out.join("\n");
    } },

  { id: "cl-sigv4-scope-parse", name: "AWS SigV4 Authorization Parser", cat: "cloud", desc: "Parse an AWS SigV4 Authorization header into its credential scope, signed headers and signature.", tags: ["aws", "sigv4", "authorization", "header", "parse"],
    inputs: [{ k: "hdr", label: "Authorization header value", type: "textarea", rows: 4, placeholder: "AWS4-HMAC-SHA256 Credential=AKIA.../20240101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcd" }],
    run(v) {
      const h = S(v.hdr).trim();
      if (!h) return "";
      if (!/^AWS4-HMAC-SHA256/.test(h)) return { error: "Expected a header starting with AWS4-HMAC-SHA256." };
      const cred = h.match(/Credential=([^,\s]+)/);
      const signed = h.match(/SignedHeaders=([^,\s]+)/);
      const sig = h.match(/Signature=([0-9a-fA-F]+)/);
      const out = [`algorithm      AWS4-HMAC-SHA256`];
      if (cred) {
        const c = cred[1].split("/");
        out.push(`credential     ${cred[1]}`);
        if (c.length === 5) out.push(`  access key   ${c[0]}`, `  date         ${c[1]}`, `  region       ${c[2]}`, `  service      ${c[3]}`, `  terminator   ${c[4]}`);
      }
      if (signed) out.push(`signed headers ${signed[1].split(";").join(", ")}`);
      if (sig) out.push(`signature      ${sig[1].slice(0, 16)}... (${sig[1].length} hex chars)`);
      return out.join("\n");
    } },

  { id: "cl-ecr-url-parse", name: "Amazon ECR URI Parser", cat: "cloud", desc: "Parse an Amazon ECR image URI into account, region, repository and tag or digest.", tags: ["aws", "ecr", "registry", "image", "parse"],
    inputs: [{ k: "uri", label: "ECR image URI", type: "text", placeholder: "123456789012.dkr.ecr.us-east-1.amazonaws.com/app:1.2.3" }],
    run(v) {
      const u = S(v.uri).trim();
      if (!u) return "";
      const m = u.match(/^(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?\/([^:@]+)(?::([^@]+))?(?:@(.+))?$/i);
      if (!m) return { error: "Not an ECR URI (expected <acct>.dkr.ecr.<region>.amazonaws.com/<repo>[:tag][@digest])." };
      return lines([`account    ${m[1]}`, `region     ${m[2]}`, `repository ${m[3]}`, `tag        ${m[4] || "(none)"}`, `digest     ${m[5] || "(none)"}`]);
    } },

  // ======================= AWS: VPC / network =======================
  { id: "cl-vpc-subnet-plan", name: "VPC Subnet Planner", cat: "cloud", desc: "Split a VPC CIDR into equal subnets of a chosen prefix and show each subnet's usable host range (AWS reserves 5 IPs per subnet).", tags: ["aws", "vpc", "subnet", "cidr", "plan"],
    inputs: [
      { k: "cidr", label: "VPC CIDR", type: "text", placeholder: "10.0.0.0/16" },
      { k: "prefix", label: "Subnet prefix", type: "range", min: 16, max: 28, step: 1, value: 24 },
      { k: "limit", label: "Max subnets to list", type: "range", min: 1, max: 64, step: 1, value: 8 },
    ],
    run(v) {
      const net = parseCidr(v.cidr);
      if (!net) return { error: "Enter a valid CIDR like 10.0.0.0/16." };
      const prefix = Number(v.prefix);
      if (prefix < net.bits) return { error: `Subnet prefix /${prefix} must be >= VPC prefix /${net.bits}.` };
      if (prefix > 28) return { error: "AWS subnets cannot be smaller than /28." };
      const count = 2 ** (prefix - net.bits);
      const limit = Math.min(count, Number(v.limit) || 8);
      const subSize = 2 ** (32 - prefix);
      const out = [`VPC ${intToIp(net.network)}/${net.bits} -> ${count} x /${prefix} subnet(s). Showing ${limit}.`, `Each /${prefix}: ${subSize} addresses, ${Math.max(0, subSize - 5)} usable (AWS reserves 5).`, ""];
      for (let i = 0; i < limit; i++) {
        const sNet = (net.network + i * subSize) >>> 0;
        const first = (sNet + 4) >>> 0; // .0 net, .1 router, .2 DNS, .3 reserved -> first usable is +4
        const last = (sNet + subSize - 2) >>> 0; // -1 broadcast
        out.push(`${intToIp(sNet)}/${prefix}  usable ${intToIp(first)} - ${intToIp(last)}`);
      }
      if (limit < count) out.push(`... (${count - limit} more)`);
      return out.join("\n");
    } },

  { id: "cl-vpc-reserved-ips", name: "VPC Reserved IP Lister", cat: "cloud", desc: "List the five addresses AWS reserves in every VPC subnet and the first and last usable host.", tags: ["aws", "vpc", "subnet", "reserved", "ip"],
    inputs: [{ k: "cidr", label: "Subnet CIDR", type: "text", placeholder: "10.0.1.0/24" }],
    run(v) {
      const net = parseCidr(v.cidr);
      if (!net) return { error: "Enter a valid subnet CIDR like 10.0.1.0/24." };
      if (net.bits > 28) return { error: "AWS subnets are /28 or larger." };
      const n = net.network;
      return lines([
        `Subnet ${intToIp(n)}/${net.bits}`,
        `${intToIp(n)}          Network address (reserved)`,
        `${intToIp((n + 1) >>> 0)}          Reserved: VPC router`,
        `${intToIp((n + 2) >>> 0)}          Reserved: Amazon DNS (.2 in base CIDR)`,
        `${intToIp((n + 3) >>> 0)}          Reserved: future use`,
        `${intToIp(net.bcast)}          Network broadcast (reserved, not used by AWS)`,
        ``,
        `First usable: ${intToIp((n + 4) >>> 0)}`,
        `Last usable : ${intToIp((net.bcast - 1) >>> 0)}`,
        `Usable hosts: ${Math.max(0, net.size - 5)}`,
      ]);
    } },

  { id: "cl-vpc-cidr-check", name: "VPC CIDR Validator", cat: "cloud", desc: "Check whether a CIDR block is allowed for an AWS VPC (prefix /16-/28) and whether it uses private RFC 1918 space.", tags: ["aws", "vpc", "cidr", "validate", "rfc1918"],
    inputs: [{ k: "cidr", label: "VPC CIDR", type: "text", placeholder: "10.0.0.0/16" }],
    run(v) {
      const net = parseCidr(v.cidr);
      if (!net) return { error: "Enter a valid CIDR like 10.0.0.0/16." };
      const errs = [];
      if (net.bits < 16 || net.bits > 28) errs.push(`prefix /${net.bits} is outside the AWS VPC range /16 to /28`);
      if (net.base !== net.network) errs.push(`host bits are set; the network address is ${intToIp(net.network)}/${net.bits}`);
      const ip = net.network;
      const priv = (ip >>> 24) === 10 || ((ip >>> 20) === 0xac1) || ((ip >>> 16) === 0xc0a8); // 10/8, 172.16/12, 192.168/16
      const note = priv ? "Uses private RFC 1918 space (recommended for VPCs)." : "NOT RFC 1918 private space — public/overlapping ranges can cause routing problems.";
      return (errs.length ? `ISSUES:\n- ${errs.join("\n- ")}\n\n` : `Valid AWS VPC CIDR: ${intToIp(net.network)}/${net.bits}\n`) + note + `\nAddresses: ${net.size}`;
    } },

  { id: "cl-cidr-overlap", name: "CIDR Overlap Checker", cat: "cloud", desc: "Check whether two CIDR blocks overlap (useful before VPC peering or merging networks).", tags: ["cidr", "overlap", "vpc", "peering", "network"],
    inputs: [
      { k: "a", label: "CIDR A", type: "text", placeholder: "10.0.0.0/16" },
      { k: "b", label: "CIDR B", type: "text", placeholder: "10.0.5.0/24" },
    ],
    run(v) {
      const A = parseCidr(v.a), B = parseCidr(v.b);
      if (!A || !B) return { error: "Enter two valid CIDRs like 10.0.0.0/16." };
      const overlap = A.network <= B.bcast && B.network <= A.bcast;
      if (!overlap) return `No overlap.\nA ${intToIp(A.network)} - ${intToIp(A.bcast)}\nB ${intToIp(B.network)} - ${intToIp(B.bcast)}\nThese can be peered without CIDR conflict.`;
      const rel = A.bits < B.bits ? "A contains B" : B.bits < A.bits ? "B contains A" : "A equals B";
      return `OVERLAP (${rel}).\nA ${intToIp(A.network)} - ${intToIp(A.bcast)}\nB ${intToIp(B.network)} - ${intToIp(B.bcast)}\nVPC peering will be rejected while these ranges overlap.`;
    } },

  { id: "cl-sg-rule-explain", name: "Security Group Rule Explainer", cat: "cloud", desc: "Explain a single security-group rule and flag it if it exposes a sensitive port to the whole internet.", tags: ["aws", "security group", "firewall", "explain"],
    inputs: [
      { k: "dir", label: "Direction", type: "select", opts: ["Inbound", "Outbound"], value: "Inbound" },
      { k: "proto", label: "Protocol", type: "select", opts: ["tcp", "udp", "icmp", "-1 (all)"], value: "tcp" },
      { k: "from", label: "From port", type: "text", placeholder: "22" },
      { k: "to", label: "To port", type: "text", placeholder: "22" },
      { k: "cidr", label: "Source/Dest CIDR", type: "text", placeholder: "0.0.0.0/0" },
    ],
    run(v) {
      const proto = S(v.proto);
      const from = S(v.from).trim(), to = S(v.to).trim() || from;
      const cidr = S(v.cidr).trim();
      if (!cidr) return "";
      const world = cidr === "0.0.0.0/0" || cidr === "::/0";
      const portDesc = proto.startsWith("-1") ? "all protocols/ports" : from ? (from === to ? `${proto} port ${from}` : `${proto} ports ${from}-${to}`) : `${proto} (no port)`;
      const out = [`${v.dir}: allow ${portDesc} from/to ${cidr}${world ? " (THE ENTIRE INTERNET)" : ""}`];
      if (world && v.dir === "Inbound") {
        const names = [];
        const lo = parseInt(from, 10), hi = parseInt(to, 10);
        for (const [p, nm] of Object.entries(RISKY_PORTS)) { const pn = Number(p); if (proto.startsWith("-1") || (!isNaN(lo) && pn >= lo && pn <= (isNaN(hi) ? lo : hi))) names.push(`${p} (${nm})`); }
        if (proto.startsWith("-1")) out.push("WARNING: all ports open to the internet — critical exposure.");
        else if (names.length) out.push("WARNING: exposes sensitive service(s) to the internet: " + names.join(", "));
        else out.push("Open to the internet; ensure the service behind this port is meant to be public.");
      }
      return out.join("\n");
    } },

  { id: "cl-sg-audit", name: "Security Group Rule Auditor", cat: "cloud", desc: "Audit a list of inbound rules (one per line: proto port cidr) and report sensitive ports open to the internet.", tags: ["aws", "security group", "audit", "exposure"],
    inputs: [{ k: "rules", label: "Rules (proto port cidr per line)", type: "textarea", rows: 8, placeholder: "tcp 22 0.0.0.0/0\ntcp 443 0.0.0.0/0\ntcp 3306 0.0.0.0/0" }],
    run(v) {
      const txt = S(v.rules).trim();
      if (!txt) return "";
      const findings = [];
      txt.split(/\n+/).forEach((ln, i) => {
        const parts = ln.trim().split(/[\s,]+/);
        if (parts.length < 3) return;
        const [proto, port, cidr] = parts;
        const world = cidr === "0.0.0.0/0" || cidr === "::/0";
        if (!world) return;
        const pn = Number(port);
        if (proto === "-1" || /all/i.test(proto)) findings.push(`line ${i + 1}: ALL ports open to internet — critical`);
        else if (RISKY_PORTS[pn]) findings.push(`line ${i + 1}: ${proto} ${port} (${RISKY_PORTS[pn]}) open to internet`);
        else findings.push(`line ${i + 1}: ${proto} ${port} open to internet (verify intentional)`);
      });
      return findings.length ? `${findings.length} internet-exposed rule(s):\n` + findings.join("\n") : "No rules found open to 0.0.0.0/0 or ::/0.";
    } },

  // ======================= GCP =======================
  { id: "cl-gcp-resource-parse", name: "GCP Resource Name Parser", cat: "cloud", desc: "Parse a Google Cloud full or relative resource name into its service and path segments (projects/zones/instances etc).", tags: ["gcp", "resource", "name", "parse"],
    inputs: [{ k: "name", label: "Resource name", type: "text", placeholder: "//compute.googleapis.com/projects/p/zones/us-central1-a/instances/vm1" }],
    run(v) {
      let n = S(v.name).trim();
      if (!n) return "";
      const out = [];
      let m = n.match(/^\/\/([^/]+)\/(.+)$/);
      if (m) { out.push(`service    ${m[1]}`); n = m[2]; } else { out.push(`service    (relative name — no service host)`); }
      const seg = n.replace(/^\//, "").split("/");
      if (seg.length % 2 !== 0) out.push("note: expected collection/id pairs; path has an odd number of segments");
      for (let i = 0; i + 1 < seg.length; i += 2) out.push(`${seg[i].padEnd(12)} ${seg[i + 1]}`);
      return lines(out);
    } },

  { id: "cl-gcp-resource-build", name: "GCP Resource Name Builder", cat: "cloud", desc: "Build a Google Cloud relative resource name from project, location-type, location and resource.", tags: ["gcp", "resource", "name", "build"],
    inputs: [
      { k: "project", label: "Project ID", type: "text", placeholder: "my-project" },
      { k: "locType", label: "Location type", type: "select", opts: ["(none)", "zones", "regions", "locations", "global"], value: "zones" },
      { k: "location", label: "Location", type: "text", placeholder: "us-central1-a" },
      { k: "collection", label: "Resource collection", type: "text", placeholder: "instances" },
      { k: "id", label: "Resource ID", type: "text", placeholder: "vm1" },
    ],
    run(v) {
      const proj = S(v.project).trim();
      if (!proj) return "";
      const parts = [`projects/${proj}`];
      const lt = S(v.locType);
      if (lt === "global") parts.push("global");
      else if (lt !== "(none)" && S(v.location).trim()) parts.push(`${lt}/${S(v.location).trim()}`);
      if (S(v.collection).trim() && S(v.id).trim()) parts.push(`${S(v.collection).trim()}/${S(v.id).trim()}`);
      return parts.join("/");
    } },

  { id: "cl-gcs-url-parse", name: "GCS URL Parser", cat: "cloud", desc: "Parse a Google Cloud Storage URL (gs://, storage.googleapis.com or storage.cloud.google.com) into bucket and object.", tags: ["gcp", "gcs", "storage", "url", "parse"],
    inputs: [{ k: "url", label: "GCS URL", type: "text", placeholder: "gs://my-bucket/path/object.txt" }],
    run(v) {
      const u = S(v.url).trim();
      if (!u) return "";
      let m;
      if ((m = u.match(/^gs:\/\/([^/]+)\/?(.*)$/i))) return lines([`scheme  gs:// (gsutil / SDK)`, `bucket  ${m[1]}`, `object  ${m[2] || "(none)"}`]);
      if ((m = u.match(/^https?:\/\/storage\.(?:googleapis\.com|cloud\.google\.com)\/([^/?]+)\/?([^?]*)/i))) return lines([`style   path-style`, `bucket  ${m[1]}`, `object  ${m[2] || "(none)"}`]);
      if ((m = u.match(/^https?:\/\/([^.]+)\.storage\.googleapis\.com\/?([^?]*)/i))) return lines([`style   virtual-hosted`, `bucket  ${m[1]}`, `object  ${m[2] || "(none)"}`]);
      return { error: "Did not recognise this as a GCS URL." };
    } },

  { id: "cl-gcs-name-validate", name: "GCS Bucket Name Validator", cat: "cloud", desc: "Check a bucket name against Google Cloud Storage naming rules.", tags: ["gcp", "gcs", "bucket", "naming", "validate"],
    inputs: [{ k: "name", label: "Bucket name", type: "text", placeholder: "my-bucket-name" }],
    run(v) {
      const n = S(v.name).trim();
      if (!n) return "";
      const errs = [];
      const dotted = n.includes(".");
      if (!dotted && (n.length < 3 || n.length > 63)) errs.push("without dots must be 3-63 characters");
      if (dotted && n.length > 222) errs.push("with dots must be 222 characters or fewer");
      if (!/^[a-z0-9._-]+$/.test(n)) errs.push("only lowercase letters, digits, hyphens, underscores and dots allowed");
      if (/[A-Z]/.test(n)) errs.push("no uppercase letters");
      if (!/^[a-z0-9]/.test(n) || !/[a-z0-9]$/.test(n)) errs.push("must start and end with a letter or digit");
      if (/^\d+\.\d+\.\d+\.\d+$/.test(n)) errs.push("must not be an IP address");
      if (/^goog/.test(n)) errs.push("must not start with the prefix 'goog'");
      if (/google|g00gle|g0ogle|go0gle/.test(n)) errs.push("must not contain 'google' or close misspellings");
      if (dotted && n.split(".").some((p) => p.length > 63)) errs.push("each dot-separated component must be 63 characters or fewer");
      return errs.length ? `INVALID: ${n}\n- ` + errs.join("\n- ") : `VALID: ${n} satisfies the GCS naming rules (names are globally unique).`;
    } },

  { id: "cl-gcp-iam-member-explain", name: "GCP IAM Member Explainer", cat: "cloud", desc: "Explain a Google Cloud IAM member identifier and warn when it grants public (allUsers / allAuthenticatedUsers) access.", tags: ["gcp", "iam", "member", "binding", "public"],
    inputs: [{ k: "member", label: "IAM member", type: "text", placeholder: "serviceAccount:app@my-project.iam.gserviceaccount.com" }],
    run(v) {
      const m = S(v.member).trim();
      if (!m) return "";
      const T = {
        "allUsers": "ANYONE on the internet, authenticated or not. PUBLIC — almost never appropriate.",
        "allAuthenticatedUsers": "Any user with a Google account (incl. other organisations). Effectively PUBLIC.",
      };
      if (T[m]) return `${m}\n  ${T[m]}`;
      const i = m.indexOf(":");
      if (i < 0) return { error: "Expected type:identifier, e.g. user:alice@example.com." };
      const type = m.slice(0, i), id = m.slice(i + 1);
      const D = {
        user: "A specific Google account (person).",
        serviceAccount: "A service account (non-human workload identity).",
        group: "A Google Group; membership is managed in the group.",
        domain: "Every account in a Google Workspace / Cloud Identity domain.",
        principal: "A single workforce/workload identity federation principal.",
        principalSet: "A set of federated principals (e.g. a whole pool or attribute).",
        deleted: "A deleted principal still present in a binding (should be cleaned up).",
      };
      return `type  ${type} — ${D[type] || "unknown member type"}\nid    ${id}`;
    } },

  { id: "cl-gcr-parse", name: "GCP Image Registry Parser", cat: "cloud", desc: "Parse a Google Artifact Registry or Container Registry image reference into host, project, repo and image.", tags: ["gcp", "artifact registry", "gcr", "image", "parse"],
    inputs: [{ k: "ref", label: "Image reference", type: "text", placeholder: "us-docker.pkg.dev/my-project/my-repo/app:1.0" }],
    run(v) {
      const r = S(v.ref).trim();
      if (!r) return "";
      let m;
      if ((m = r.match(/^([a-z0-9-]+)-docker\.pkg\.dev\/([^/]+)\/([^/]+)\/([^:@]+)(?::([^@]+))?(?:@(.+))?$/i)))
        return lines([`registry   Artifact Registry`, `location   ${m[1]}`, `project    ${m[2]}`, `repository ${m[3]}`, `image      ${m[4]}`, `tag        ${m[5] || "(none)"}`, `digest     ${m[6] || "(none)"}`]);
      if ((m = r.match(/^(gcr\.io|[a-z]+\.gcr\.io)\/([^/]+)\/([^:@]+)(?::([^@]+))?(?:@(.+))?$/i)))
        return lines([`registry   Container Registry (${m[1]})`, `project    ${m[2]}`, `image      ${m[3]}`, `tag        ${m[4] || "(none)"}`, `digest     ${m[5] || "(none)"}`]);
      return { error: "Not a recognised GCR/Artifact Registry reference." };
    } },

  { id: "cl-gcp-sa-key-explain", name: "GCP Service Account Key Explainer", cat: "cloud", desc: "Summarise a GCP service account key JSON (project, client email, key id) and warn it is a long-lived credential.", tags: ["gcp", "service account", "key", "credential"],
    inputs: [{ k: "json", label: "SA key JSON", type: "textarea", rows: 8, placeholder: '{"type":"service_account","project_id":"p","client_email":"a@p.iam.gserviceaccount.com",...}' }],
    run(v) {
      const txt = S(v.json).trim();
      if (!txt) return "";
      let k; try { k = JSON.parse(txt); } catch (e) { return { error: "Not valid JSON." }; }
      if (k.type !== "service_account") return { error: 'JSON "type" is not "service_account".' };
      return lines([
        `type            ${k.type}`,
        `project_id      ${k.project_id || "(missing)"}`,
        `client_email    ${k.client_email || "(missing)"}`,
        `client_id       ${k.client_id || "(missing)"}`,
        `private_key_id  ${k.private_key_id || "(missing)"}`,
        `private_key     ${k.private_key ? "present (" + k.private_key.length + " chars) — SECRET" : "(missing)"}`,
        ``,
        `WARNING: downloaded SA keys are long-lived credentials that do not rotate.`,
        `Prefer Workload Identity Federation or short-lived tokens; never commit this file.`,
      ]);
    } },

  // ======================= Azure =======================
  { id: "cl-azure-resourceid-parse", name: "Azure Resource ID Parser", cat: "cloud", desc: "Parse an Azure resource ID into subscription, resource group, provider and resource type/name.", tags: ["azure", "resource id", "parse"],
    inputs: [{ k: "id", label: "Resource ID", type: "text", placeholder: "/subscriptions/0000.../resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct" }],
    run(v) {
      const id = S(v.id).trim();
      if (!id) return "";
      const seg = id.replace(/^\//, "").split("/");
      const out = {};
      for (let i = 0; i + 1 < seg.length; i += 2) {
        const k = seg[i].toLowerCase();
        if (k === "subscriptions") out.subscription = seg[i + 1];
        else if (k === "resourcegroups") out.resourceGroup = seg[i + 1];
        else if (k === "providers") out.provider = seg[i + 1];
      }
      // resource type/name after providers
      const pIdx = seg.findIndex((s) => s.toLowerCase() === "providers");
      let typeName = "";
      if (pIdx >= 0) { const rest = seg.slice(pIdx + 2); if (rest.length) typeName = `${rest.filter((_, i) => i % 2 === 0).join("/")} = ${rest.filter((_, i) => i % 2 === 1).join("/")}`; }
      if (!out.subscription && !out.provider) return { error: "Did not look like an Azure resource ID." };
      return lines([
        `subscription   ${out.subscription || "(none)"}`,
        `resourceGroup  ${out.resourceGroup || "(none)"}`,
        `provider       ${out.provider || "(none)"}`,
        typeName ? `resource       ${typeName}` : null,
      ]);
    } },

  { id: "cl-azure-resourceid-build", name: "Azure Resource ID Builder", cat: "cloud", desc: "Build an Azure resource ID from subscription, resource group, provider, type and name.", tags: ["azure", "resource id", "build"],
    inputs: [
      { k: "sub", label: "Subscription ID", type: "text", placeholder: "00000000-0000-0000-0000-000000000000" },
      { k: "rg", label: "Resource group", type: "text", placeholder: "my-rg" },
      { k: "provider", label: "Provider", type: "text", placeholder: "Microsoft.Storage" },
      { k: "type", label: "Resource type", type: "text", placeholder: "storageAccounts" },
      { k: "name", label: "Resource name", type: "text", placeholder: "myacct" },
    ],
    run(v) {
      const sub = S(v.sub).trim();
      if (!sub) return "";
      const rg = S(v.rg).trim(), provider = S(v.provider).trim(), type = S(v.type).trim(), name = S(v.name).trim();
      let p = `/subscriptions/${sub}`;
      if (rg) p += `/resourceGroups/${rg}`;
      if (provider && type && name) p += `/providers/${provider}/${type}/${name}`;
      else if (provider) return { error: "Provider set but type and name are required too." };
      return p;
    } },

  { id: "cl-azure-blob-url-parse", name: "Azure Blob URL Parser", cat: "cloud", desc: "Parse an Azure Blob Storage URL into storage account, container and blob.", tags: ["azure", "blob", "storage", "url", "parse"],
    inputs: [{ k: "url", label: "Blob URL", type: "text", placeholder: "https://myacct.blob.core.windows.net/container/path/blob.txt" }],
    run(v) {
      const u = S(v.url).trim();
      if (!u) return "";
      const m = u.match(/^https?:\/\/([^.]+)\.blob\.core\.windows\.net\/([^/?]+)\/?([^?]*)/i);
      if (!m) return { error: "Expected https://<account>.blob.core.windows.net/<container>/<blob>." };
      return lines([`account    ${m[1]}`, `container  ${m[2]}`, `blob       ${m[3] || "(none)"}`]);
    } },

  { id: "cl-azure-sas-explain", name: "Azure SAS Token Explainer", cat: "cloud", desc: "Decode an Azure Shared Access Signature query string: services, resource types, permissions, validity window and allowed IP/protocol.", tags: ["azure", "sas", "token", "storage", "expiry"],
    inputs: [{ k: "sas", label: "SAS query string or URL", type: "textarea", rows: 4, placeholder: "?sv=2022-11-02&ss=b&srt=co&sp=rl&se=2025-01-01T00:00:00Z&spr=https&sig=..." }],
    run(v) {
      const s = S(v.sas).trim();
      if (!s) return "";
      const q = s.includes("=") && !s.includes("?") ? qparse("?" + s) : qparse(s);
      if (!q.sig && !q.sv) return { error: "No SAS parameters found (expected sv, sp, se, sig...)." };
      const PERM = { r: "read", w: "write", d: "delete", l: "list", a: "add", c: "create", u: "update", p: "process", t: "tag", f: "filter", i: "set immutability", y: "permanent delete", x: "delete version" };
      const SVC = { b: "blob", q: "queue", t: "table", f: "file" };
      const SRT = { s: "service", c: "container", o: "object" };
      const out = [];
      if (q.sv) out.push(`sv  signed version     ${q.sv}`);
      if (q.ss) out.push(`ss  services           ${q.ss.split("").map((c) => SVC[c] || c).join(", ")}`);
      if (q.srt) out.push(`srt resource types     ${q.srt.split("").map((c) => SRT[c] || c).join(", ")}`);
      if (q.sr) out.push(`sr  signed resource    ${q.sr}`);
      if (q.sp) out.push(`sp  permissions        ${q.sp.split("").map((c) => PERM[c] || c).join(", ")}`);
      if (q.st) out.push(`st  start              ${q.st}`);
      if (q.se) out.push(`se  expiry             ${q.se}`);
      if (q.sip) out.push(`sip allowed IP(s)      ${q.sip}`);
      if (q.spr) out.push(`spr protocols          ${q.spr}`);
      if (q.sig) out.push(`sig signature          present (${q.sig.length} chars)`);
      if (q.se) { const exp = Date.parse(q.se); if (!isNaN(exp)) out.push(exp < Date.now() ? `\nNOTE: this SAS has EXPIRED.` : `\nValid until ${new Date(exp).toISOString()}.`); }
      if (!q.spr || !/https/i.test(q.spr)) out.push(`WARNING: SAS does not restrict to https only (spr).`);
      return out.join("\n");
    } },

  { id: "cl-azure-storage-name-validate", name: "Azure Storage Account Name Validator", cat: "cloud", desc: "Check a name against Azure storage account naming rules (3-24 lowercase letters and digits).", tags: ["azure", "storage", "naming", "validate"],
    inputs: [{ k: "name", label: "Storage account name", type: "text", placeholder: "mystorageacct01" }],
    run(v) {
      const n = S(v.name).trim();
      if (!n) return "";
      const errs = [];
      if (n.length < 3 || n.length > 24) errs.push("must be 3-24 characters");
      if (!/^[a-z0-9]+$/.test(n)) errs.push("only lowercase letters and digits (no hyphens, dots or uppercase)");
      return errs.length ? `INVALID: ${n}\n- ` + errs.join("\n- ") : `VALID: ${n} satisfies Azure storage account naming rules (must also be globally unique).`;
    } },

  { id: "cl-acr-parse", name: "Azure Container Registry Parser", cat: "cloud", desc: "Parse an Azure Container Registry image reference into registry, repository and tag or digest.", tags: ["azure", "acr", "registry", "image", "parse"],
    inputs: [{ k: "ref", label: "Image reference", type: "text", placeholder: "myregistry.azurecr.io/app/web:1.0" }],
    run(v) {
      const r = S(v.ref).trim();
      if (!r) return "";
      const m = r.match(/^([a-z0-9]+)\.azurecr\.io\/([^:@]+)(?::([^@]+))?(?:@(.+))?$/i);
      if (!m) return { error: "Expected <registry>.azurecr.io/<repository>[:tag][@digest]." };
      return lines([`registry   ${m[1]}.azurecr.io`, `repository ${m[2]}`, `tag        ${m[3] || "(none)"}`, `digest     ${m[4] || "(none)"}`]);
    } },

  { id: "cl-azure-rbac-roles-ref", name: "Azure Built-in Role Reference", cat: "cloud", desc: "Reference of broad Azure built-in RBAC roles and what they allow.", tags: ["azure", "rbac", "role", "reference"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "owner, contributor..." }],
    run(v) {
      const R = [
        ["Owner", "Full access to all resources INCLUDING the right to delegate access to others. Highest privilege."],
        ["Contributor", "Create and manage all resource types but CANNOT grant access (no role assignments)."],
        ["Reader", "View all resources; cannot make changes."],
        ["User Access Administrator", "Manage user access to Azure resources (role assignments) — escalation path, grant sparingly."],
      ];
      const q = S(v.q).toLowerCase().trim();
      const m = R.filter(([a, b]) => !q || a.toLowerCase().includes(q) || b.toLowerCase().includes(q));
      return m.length ? m.map(([a, b]) => `${a}\n    ${b}`).join("\n") : "No matches.";
    } },

  // ======================= Kubernetes =======================
  { id: "cl-k8s-rbac-explain", name: "Kubernetes RBAC Rule Explainer", cat: "cloud", desc: "Explain an RBAC policy rule (apiGroups/resources/verbs) in plain English and flag dangerous grants.", tags: ["kubernetes", "rbac", "role", "explain", "privilege"],
    inputs: [
      { k: "apiGroups", label: "apiGroups", type: "text", placeholder: '"" (core), apps, *' },
      { k: "resources", label: "resources", type: "text", placeholder: "pods, secrets, *" },
      { k: "verbs", label: "verbs", type: "text", placeholder: "get, list, create, *" },
    ],
    run(v) {
      const groups = S(v.apiGroups).split(/[\s,]+/).filter(Boolean);
      const res = S(v.resources).split(/[\s,]+/).filter(Boolean);
      const verbs = S(v.verbs).split(/[\s,]+/).filter(Boolean).map((x) => x.toLowerCase());
      if (!res.length || !verbs.length) return "";
      const out = [`Allows: ${verbs.join(", ")} on ${res.join(", ")} in apiGroup(s) ${groups.map((g) => g === '""' ? "core" : g).join(", ") || "core"}`];
      const w = [];
      if (verbs.includes("*") && res.includes("*")) w.push("verbs:* on resources:* is cluster-admin-equivalent within its scope.");
      if (res.includes("secrets") && (verbs.includes("get") || verbs.includes("list") || verbs.includes("*"))) w.push("can read Secrets — may expose credentials/tokens.");
      if (res.some((r) => r === "pods/exec" || r === "pods/attach")) w.push("pods/exec or pods/attach — can run commands in containers.");
      if (res.includes("pods") && (verbs.includes("create") || verbs.includes("*"))) w.push("can create Pods — may mount secrets or escalate via a privileged pod.");
      if (verbs.includes("escalate") || verbs.includes("bind")) w.push("verb escalate/bind on roles lets the subject grant themselves more permissions.");
      if (verbs.includes("impersonate")) w.push("impersonate lets the subject act as other users/groups/service accounts.");
      if (res.some((r) => r === "nodes" || r === "nodes/proxy")) w.push("node access can reach the kubelet and other pods' data.");
      if (w.length) out.push("", "WARNINGS:", ...w.map((x) => "- " + x));
      return out.join("\n");
    } },

  { id: "cl-k8s-rbac-verbs-ref", name: "Kubernetes RBAC Verb Reference", cat: "cloud", desc: "Reference of Kubernetes RBAC verbs, including the special escalate/bind/impersonate verbs.", tags: ["kubernetes", "rbac", "verbs", "reference"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "escalate, watch..." }],
    run(v) {
      const V = [
        ["get", "Read a single named resource."], ["list", "Read a collection (returns all objects and their data)."],
        ["watch", "Stream changes to a resource/collection."], ["create", "Create new resources."],
        ["update", "Replace an existing resource."], ["patch", "Partially modify a resource."],
        ["delete", "Delete a single resource."], ["deletecollection", "Delete a whole collection at once."],
        ["escalate", "(special, on roles) Create/update a Role with more permissions than you hold."],
        ["bind", "(special, on roles) Reference a Role in a RoleBinding you create."],
        ["impersonate", "(special) Act as another user, group or service account."],
        ["use", "(special, on PodSecurityPolicies - deprecated) Use a named PSP."],
        ["approve", "(special, on certificatesigningrequests) Approve a CSR."],
      ];
      const q = S(v.q).toLowerCase().trim();
      const m = V.filter(([a, b]) => !q || a.includes(q) || b.toLowerCase().includes(q));
      return m.length ? m.map(([a, b]) => `${a.padEnd(17)} ${b}`).join("\n") : "No matches.";
    } },

  { id: "cl-k8s-rolebinding-build", name: "Kubernetes Role + RoleBinding Builder", cat: "cloud", desc: "Generate a namespaced Role and a RoleBinding YAML granting chosen verbs on resources to a subject.", tags: ["kubernetes", "rbac", "role", "rolebinding", "yaml", "build"],
    inputs: [
      { k: "ns", label: "Namespace", type: "text", value: "default" },
      { k: "roleName", label: "Role name", type: "text", value: "reader" },
      { k: "apiGroups", label: "apiGroups", type: "text", value: '""' },
      { k: "resources", label: "resources", type: "text", value: "pods" },
      { k: "verbs", label: "verbs", type: "text", value: "get,list,watch" },
      { k: "subjectKind", label: "Subject kind", type: "select", opts: ["ServiceAccount", "User", "Group"], value: "ServiceAccount" },
      { k: "subject", label: "Subject name", type: "text", value: "app-sa" },
    ],
    run(v) {
      const res = S(v.resources).split(/[\s,]+/).filter(Boolean);
      const verbs = S(v.verbs).split(/[\s,]+/).filter(Boolean);
      const groups = S(v.apiGroups).split(/[\s,]+/).filter(Boolean);
      if (!res.length || !verbs.length) return "";
      const ns = S(v.ns).trim() || "default";
      const rn = S(v.roleName).trim() || "role";
      const yl = (arr) => arr.map((x) => (x === '""' ? '""' : x)).map((x) => `  - ${x}`).join("\n");
      const subjLine = v.subjectKind === "ServiceAccount" ? `  - kind: ServiceAccount\n    name: ${S(v.subject).trim()}\n    namespace: ${ns}` : `  - kind: ${v.subjectKind}\n    name: ${S(v.subject).trim()}\n    apiGroup: rbac.authorization.k8s.io`;
      return [
        `apiVersion: rbac.authorization.k8s.io/v1`,
        `kind: Role`,
        `metadata:`,
        `  name: ${rn}`,
        `  namespace: ${ns}`,
        `rules:`,
        `  - apiGroups:`,
        yl(groups.length ? groups : ['""']),
        `    resources:`,
        yl(res),
        `    verbs:`,
        yl(verbs),
        `---`,
        `apiVersion: rbac.authorization.k8s.io/v1`,
        `kind: RoleBinding`,
        `metadata:`,
        `  name: ${rn}-binding`,
        `  namespace: ${ns}`,
        `subjects:`,
        subjLine,
        `roleRef:`,
        `  kind: Role`,
        `  name: ${rn}`,
        `  apiGroup: rbac.authorization.k8s.io`,
      ].join("\n");
    } },

  { id: "cl-k8s-can-i", name: "kubectl auth can-i Builder", cat: "cloud", desc: "Build a kubectl auth can-i command to test whether a subject may perform an action.", tags: ["kubernetes", "rbac", "kubectl", "can-i", "builder"],
    inputs: [
      { k: "verb", label: "Verb", type: "text", value: "get" },
      { k: "resource", label: "Resource", type: "text", value: "pods" },
      { k: "ns", label: "Namespace (blank = current)", type: "text", placeholder: "default" },
      { k: "as", label: "Impersonate (--as, optional)", type: "text", placeholder: "system:serviceaccount:default:app-sa" },
      { k: "all", label: "List everything (--list)", type: "checkbox", value: false },
    ],
    run(v) {
      if (v.all) return `kubectl auth can-i --list${S(v.ns).trim() ? " -n " + S(v.ns).trim() : ""}${S(v.as).trim() ? " --as " + S(v.as).trim() : ""}`;
      const verb = S(v.verb).trim(), res = S(v.resource).trim();
      if (!verb || !res) return "";
      let c = `kubectl auth can-i ${verb} ${res}`;
      if (S(v.ns).trim()) c += ` -n ${S(v.ns).trim()}`;
      if (S(v.as).trim()) c += ` --as ${S(v.as).trim()}`;
      return c;
    } },

  { id: "cl-k8s-securitycontext", name: "Kubernetes securityContext Advisor", cat: "cloud", desc: "Review container securityContext settings and report which hardening controls are missing or unsafe.", tags: ["kubernetes", "securitycontext", "pod", "harden", "advisor"],
    inputs: [
      { k: "runAsNonRoot", label: "runAsNonRoot", type: "checkbox", value: false },
      { k: "privileged", label: "privileged", type: "checkbox", value: false },
      { k: "allowPrivEsc", label: "allowPrivilegeEscalation", type: "checkbox", value: true },
      { k: "readOnlyRootFs", label: "readOnlyRootFilesystem", type: "checkbox", value: false },
      { k: "dropAll", label: "capabilities drop: ALL", type: "checkbox", value: false },
      { k: "seccomp", label: "seccompProfile: RuntimeDefault", type: "checkbox", value: false },
    ],
    run(v) {
      const issues = [];
      if (v.privileged) issues.push("[HIGH] privileged: true disables almost all isolation — remove it.");
      if (!v.runAsNonRoot) issues.push("[HIGH] runAsNonRoot is not set — container may run as UID 0 (root).");
      if (v.allowPrivEsc) issues.push("[MED] allowPrivilegeEscalation should be false (setuid binaries can gain privileges).");
      if (!v.dropAll) issues.push("[MED] capabilities are not dropped — add drop: [\"ALL\"] and only add back what is needed.");
      if (!v.readOnlyRootFs) issues.push("[LOW] readOnlyRootFilesystem is not set — prevents tampering with the image at runtime.");
      if (!v.seccomp) issues.push("[LOW] seccompProfile RuntimeDefault is not set — restricts dangerous syscalls.");
      return issues.length ? `${issues.length} recommendation(s):\n` + issues.join("\n") : "Good: matches the restricted Pod Security Standard baseline for these fields.";
    } },

  { id: "cl-k8s-securitycontext-yaml", name: "Hardened securityContext Builder", cat: "cloud", desc: "Emit a hardened container securityContext YAML block meeting the restricted Pod Security Standard.", tags: ["kubernetes", "securitycontext", "yaml", "restricted", "build"],
    inputs: [
      { k: "uid", label: "runAsUser (UID)", type: "text", value: "1000" },
      { k: "readonly", label: "read-only root filesystem", type: "checkbox", value: true },
      { k: "netbind", label: "allow NET_BIND_SERVICE (ports <1024)", type: "checkbox", value: false },
    ],
    run(v) {
      const uid = S(v.uid).trim() || "1000";
      const caps = v.netbind ? `    drop: ["ALL"]\n    add: ["NET_BIND_SERVICE"]` : `    drop: ["ALL"]`;
      return [
        `securityContext:`,
        `  runAsNonRoot: true`,
        `  runAsUser: ${uid}`,
        `  allowPrivilegeEscalation: false`,
        `  privileged: false`,
        `  readOnlyRootFilesystem: ${v.readonly ? "true" : "false"}`,
        `  capabilities:`,
        caps,
        `  seccompProfile:`,
        `    type: RuntimeDefault`,
      ].join("\n");
    } },

  { id: "cl-k8s-capabilities-ref", name: "Container Linux Capabilities Reference", cat: "cloud", desc: "Reference of Linux capabilities for containers: which Docker grants by default and which are dangerous to add.", tags: ["kubernetes", "docker", "capabilities", "reference", "harden"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "net, admin, ptrace..." }],
    run(v) {
      const DEF = ["CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID", "SETUID", "SETFCAP", "SETPCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE"];
      const DANGER = [
        ["SYS_ADMIN", "Huge, catch-all capability — mounts, namespaces; near-root. Avoid."],
        ["SYS_PTRACE", "Trace/inspect other processes; can bypass isolation."],
        ["SYS_MODULE", "Load kernel modules — full host compromise."],
        ["SYS_BOOT", "Reboot the host."],
        ["SYS_TIME", "Change the system clock."],
        ["SYS_RAWIO", "Raw I/O port and memory access."],
        ["NET_ADMIN", "Reconfigure networking (interfaces, firewall, routing)."],
        ["NET_RAW", "Craft raw packets (spoofing, some sniffing) — granted by default."],
        ["DAC_READ_SEARCH", "Bypass file read/execute permission checks."],
        ["BPF", "Load BPF programs."],
        ["PERFMON", "Performance monitoring / some kernel introspection."],
        ["SYSLOG", "Read the kernel log (can leak KASLR offsets)."],
      ];
      const q = S(v.q).toLowerCase().trim();
      const dline = DANGER.filter(([a, b]) => !q || a.toLowerCase().includes(q) || b.toLowerCase().includes(q));
      const defShow = !q || "default".includes(q) || DEF.some((c) => c.toLowerCase().includes(q));
      const parts = [];
      if (defShow) parts.push("Docker default capabilities (14):\n  " + DEF.join(", "));
      if (dline.length) parts.push("Dangerous to add:\n" + dline.map(([a, b]) => `  ${a} — ${b}`).join("\n"));
      return parts.length ? parts.join("\n\n") : "No matches.";
    } },

  { id: "cl-k8s-pod-security-standards", name: "Pod Security Standards Reference", cat: "cloud", desc: "Summarise the Kubernetes Pod Security Standards (Privileged, Baseline, Restricted) and their key controls.", tags: ["kubernetes", "pss", "pod security", "reference"],
    inputs: [{ k: "level", label: "Level", type: "select", opts: ["All", "Privileged", "Baseline", "Restricted"], value: "All" }],
    run(v) {
      const B = {
        Privileged: "Unrestricted. No limits imposed. For trusted, system-level workloads only.",
        Baseline: lines([
          "Minimally restrictive; blocks known privilege escalations:",
          "  - no hostNetwork, hostPID, hostIPC",
          "  - no privileged containers; no hostPath volumes; host ports restricted",
          "  - no added capabilities beyond a safe set (NET_BIND_SERVICE allowed)",
          "  - no unsafe sysctls; AppArmor/SELinux/seccomp not weakened",
        ]),
        Restricted: lines([
          "Baseline PLUS strict hardening:",
          "  - runAsNonRoot: true (and no runAsUser: 0)",
          "  - allowPrivilegeEscalation: false",
          "  - capabilities: drop [\"ALL\"] (may add back only NET_BIND_SERVICE)",
          "  - seccompProfile: RuntimeDefault or Localhost",
          "  - volume types restricted to a safe set (configMap, secret, emptyDir, PVC, etc.)",
        ]),
      };
      const lvl = S(v.level);
      if (lvl !== "All") return `${lvl}\n${B[lvl]}`;
      return Object.entries(B).map(([k, val]) => `=== ${k} ===\n${val}`).join("\n\n");
    } },

  { id: "cl-k8s-netpol-builder", name: "Kubernetes NetworkPolicy Builder", cat: "cloud", desc: "Generate a NetworkPolicy YAML: a namespace default-deny, or allow ingress from a pod/namespace selector.", tags: ["kubernetes", "networkpolicy", "yaml", "zero-trust", "build"],
    inputs: [
      { k: "ns", label: "Namespace", type: "text", value: "default" },
      { k: "template", label: "Template", type: "select", opts: ["Default-deny all ingress", "Default-deny all ingress+egress", "Allow ingress from pod label"], value: "Default-deny all ingress" },
      { k: "targetLabel", label: "Target pod label (app=...)", type: "text", placeholder: "app=api" },
      { k: "fromLabel", label: "Allowed-from pod label (for allow template)", type: "text", placeholder: "app=frontend" },
      { k: "port", label: "Port (for allow template)", type: "text", placeholder: "8080" },
    ],
    run(v) {
      const ns = S(v.ns).trim() || "default";
      const t = S(v.template);
      if (t === "Allow ingress from pod label") {
        const tgt = S(v.targetLabel).trim(), from = S(v.fromLabel).trim();
        if (!tgt || !from) return { error: "Target and allowed-from pod labels are required (e.g. app=api)." };
        const [tk, tv] = tgt.split("="), [fk, fv] = from.split("=");
        const port = S(v.port).trim();
        return [
          `apiVersion: networking.k8s.io/v1`, `kind: NetworkPolicy`,
          `metadata:`, `  name: allow-${fv || "src"}-to-${tv || "dst"}`, `  namespace: ${ns}`,
          `spec:`, `  podSelector:`, `    matchLabels:`, `      ${tk}: ${tv}`,
          `  policyTypes: ["Ingress"]`, `  ingress:`, `    - from:`, `        - podSelector:`, `            matchLabels:`, `              ${fk}: ${fv}`,
          port ? `      ports:\n        - protocol: TCP\n          port: ${port}` : null,
        ].filter(Boolean).join("\n");
      }
      const egress = t.includes("egress");
      return [
        `apiVersion: networking.k8s.io/v1`, `kind: NetworkPolicy`,
        `metadata:`, `  name: default-deny${egress ? "-all" : "-ingress"}`, `  namespace: ${ns}`,
        `spec:`, `  podSelector: {}`, `  policyTypes: [${egress ? "\"Ingress\", \"Egress\"" : "\"Ingress\""}]`,
      ].join("\n");
    } },

  { id: "cl-k8s-secret-coder", name: "Kubernetes Secret Encoder / Decoder", cat: "cloud", desc: "Encode a value into a Secret data: block (base64) or decode one, with a reminder that Secrets are not encrypted by default.", tags: ["kubernetes", "secret", "base64", "encode", "decode"],
    inputs: [
      { k: "mode", label: "Mode", type: "select", opts: ["Encode (value -> data)", "Decode (data -> value)"], value: "Encode (value -> data)" },
      { k: "key", label: "Key name", type: "text", value: "password" },
      { k: "value", label: "Value (or base64 when decoding)", type: "textarea", rows: 3, placeholder: "s3cr3t" },
    ],
    run(v, H) {
      const key = S(v.key).trim() || "key";
      const val = S(v.value);
      if (!val) return "";
      if (v.mode.startsWith("Encode")) {
        const b = H.b64encode(val);
        return `data:\n  ${key}: ${b}\n\n# base64 is ENCODING, not encryption. Enable encryption-at-rest and RBAC on Secrets.`;
      }
      try { return `${key}: ${H.b64decode(val.trim())}`; } catch (e) { return { error: "Value is not valid base64." }; }
    } },

  { id: "cl-k8s-hardening-flags", name: "Kubernetes Hardening Flags Reference", cat: "cloud", desc: "CIS-aligned reference of important kube-apiserver, kubelet and etcd security flags.", tags: ["kubernetes", "cis", "kube-bench", "apiserver", "kubelet", "harden"],
    inputs: [{ k: "q", label: "Filter (apiserver, kubelet, etcd, blank = all)", type: "text", placeholder: "kubelet" }],
    run(v) {
      const F = [
        ["apiserver", "--anonymous-auth=false", "Reject unauthenticated requests to the API server."],
        ["apiserver", "--authorization-mode=Node,RBAC", "Enforce RBAC (and Node authorizer); never AlwaysAllow."],
        ["apiserver", "--encryption-provider-config=...", "Encrypt Secrets at rest in etcd."],
        ["apiserver", "--audit-log-path=...", "Enable the audit log."],
        ["apiserver", "--profiling=false", "Disable the profiling endpoint (information disclosure)."],
        ["apiserver", "--service-account-lookup=true", "Verify SA tokens still exist in etcd."],
        ["apiserver", "--client-ca-file=...", "Require client-certificate authentication CA."],
        ["kubelet", "--anonymous-auth=false", "Reject anonymous requests to the kubelet API (port 10250)."],
        ["kubelet", "--authorization-mode=Webhook", "Delegate kubelet authz to the API server (not AlwaysAllow)."],
        ["kubelet", "--read-only-port=0", "Disable the unauthenticated read-only port 10255."],
        ["kubelet", "--protect-kernel-defaults=true", "Refuse to start if kernel tunables are unsafe."],
        ["kubelet", "--rotate-certificates=true", "Rotate kubelet client certificates automatically."],
        ["kubelet", "--make-iptables-util-chains=true", "Let the kubelet manage iptables chains."],
        ["etcd", "--client-cert-auth=true", "Require client certificates for etcd clients."],
        ["etcd", "--peer-client-cert-auth=true", "Require certificates between etcd peers."],
        ["etcd", "--auto-tls=false", "Do not auto-generate self-signed TLS (use real certs)."],
      ];
      const q = S(v.q).toLowerCase().trim();
      const m = F.filter(([c, f, d]) => !q || c.includes(q) || f.toLowerCase().includes(q) || d.toLowerCase().includes(q));
      return m.length ? m.map(([c, f, d]) => `[${c}] ${f}\n    ${d}`).join("\n") : "No matches.";
    } },

  { id: "cl-k8s-well-known-ports", name: "Kubernetes Component Port Reference", cat: "cloud", desc: "Reference of the ports used by Kubernetes control-plane and node components (attack-surface review).", tags: ["kubernetes", "ports", "reference", "attack surface"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "etcd, kubelet..." }],
    run(v) {
      const P = [
        ["6443", "kube-apiserver (HTTPS) — main API endpoint"],
        ["2379", "etcd client API — holds all cluster state and Secrets"],
        ["2380", "etcd peer communication"],
        ["10250", "kubelet API (HTTPS, authenticated) — exec/logs if authz is weak"],
        ["10255", "kubelet read-only port (unauthenticated, deprecated — should be disabled)"],
        ["10257", "kube-controller-manager (HTTPS)"],
        ["10259", "kube-scheduler (HTTPS)"],
        ["10249", "kube-proxy metrics"],
        ["30000-32767", "default NodePort service range"],
        ["53", "CoreDNS / kube-dns (TCP & UDP)"],
      ];
      const q = S(v.q).toLowerCase().trim();
      const m = P.filter(([a, b]) => !q || a.includes(q) || b.toLowerCase().includes(q));
      return m.length ? m.map(([a, b]) => `${a.padEnd(12)} ${b}`).join("\n") : "No matches.";
    } },

  { id: "cl-k8s-seccomp-ref", name: "Kubernetes seccompProfile Reference", cat: "cloud", desc: "Explain the seccompProfile types for pods and containers (RuntimeDefault, Localhost, Unconfined).", tags: ["kubernetes", "seccomp", "reference", "harden"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "default, localhost..." }],
    run(v) {
      const T = [
        ["RuntimeDefault", "Use the container runtime's default seccomp profile (blocks ~44 dangerous syscalls). Recommended."],
        ["Localhost", "Use a custom profile file on the node under the kubelet seccomp root (localhostProfile)."],
        ["Unconfined", "No seccomp filtering — all syscalls allowed. Avoid; disallowed by the Restricted standard."],
      ];
      const q = S(v.q).toLowerCase().trim();
      const m = T.filter(([a, b]) => !q || a.toLowerCase().includes(q) || b.toLowerCase().includes(q));
      return m.length ? m.map(([a, b]) => `${a}\n    ${b}`).join("\n") : "No matches.";
    } },

  // ======================= Docker / OCI =======================
  { id: "cl-dockerfile-lint", name: "Dockerfile Security Linter", cat: "cloud", desc: "Scan a Dockerfile for security smells: running as root, the latest tag, ADD vs COPY, secrets in layers and missing hardening.", tags: ["docker", "dockerfile", "lint", "security"],
    inputs: [{ k: "text", label: "Dockerfile", type: "textarea", rows: 12, placeholder: "FROM ubuntu:latest\nADD . /app\nRUN curl http://x | bash" }],
    run(v) {
      const txt = S(v.text);
      if (!txt.trim()) return "";
      const rows = txt.split(/\r?\n/);
      const findings = [];
      let sawUser = false, lastFromLatest = false, sawHealthcheck = false;
      rows.forEach((raw, i) => {
        const ln = raw.trim(); if (!ln || ln.startsWith("#")) return;
        const n = i + 1;
        const instr = (ln.match(/^(\w+)/) || [, ""])[1].toUpperCase();
        if (instr === "FROM") { lastFromLatest = /:latest\b/.test(ln) || !/:/.test(ln.replace(/\s+as\s+\w+/i, "").split(/\s+/)[1] || ""); if (lastFromLatest) findings.push(`[MED] line ${n}: FROM uses :latest or no tag — pin a specific version/digest.`); }
        if (instr === "USER") { sawUser = true; if (/^user\s+(root|0)\s*$/i.test(ln)) findings.push(`[HIGH] line ${n}: USER root — run as an unprivileged user instead.`); }
        if (instr === "ADD" && !/^add\s+--/.test(ln.toLowerCase()) && !/^add\s+http/i.test(ln)) findings.push(`[LOW] line ${n}: prefer COPY over ADD unless you need URL fetch or auto-extract.`);
        if (/\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash)/i.test(ln)) findings.push(`[HIGH] line ${n}: piping a download straight into a shell — unverified remote code execution.`);
        if (instr === "RUN" && /\bsudo\b/.test(ln)) findings.push(`[LOW] line ${n}: sudo inside RUN is usually unnecessary (build runs as root already).`);
        if (/(ENV|ARG)\s+\w*(PASS|PASSWORD|SECRET|TOKEN|KEY|APIKEY)\w*\s*=/i.test(ln)) findings.push(`[HIGH] line ${n}: possible secret baked into an image layer (ENV/ARG) — use build secrets or runtime env.`);
        if (/\b(AKIA|ASIA)[A-Z2-7]{16}\b/.test(ln)) findings.push(`[HIGH] line ${n}: looks like an AWS access key ID committed in the image.`);
        if (instr === "RUN" && /apt-get\s+install/.test(ln) && !/--no-install-recommends/.test(ln)) findings.push(`[LOW] line ${n}: apt-get install without --no-install-recommends enlarges the image.`);
        if (instr === "HEALTHCHECK") sawHealthcheck = true;
        if (instr === "EXPOSE" && /\b22\b/.test(ln)) findings.push(`[MED] line ${n}: EXPOSE 22 — running SSH inside a container is an anti-pattern.`);
      });
      if (!sawUser) findings.push(`[MED] no USER instruction — the container will run as root by default.`);
      if (!sawHealthcheck) findings.push(`[LOW] no HEALTHCHECK instruction.`);
      return findings.length ? `${findings.length} finding(s):\n` + findings.join("\n") : "No obvious issues found (heuristic lint).";
    } },

  { id: "cl-compose-lint", name: "docker-compose Security Review", cat: "cloud", desc: "Scan docker-compose YAML for risky settings: privileged, host networking/PID, docker.sock mounts, added capabilities and latest tags.", tags: ["docker", "compose", "lint", "security"],
    inputs: [{ k: "text", label: "docker-compose.yml", type: "textarea", rows: 12, placeholder: "services:\n  app:\n    image: nginx:latest\n    privileged: true" }],
    run(v) {
      const txt = S(v.text);
      if (!txt.trim()) return "";
      const findings = [];
      txt.split(/\r?\n/).forEach((raw, i) => {
        const ln = raw.trim(); const n = i + 1;
        if (/^privileged:\s*true/i.test(ln)) findings.push(`[HIGH] line ${n}: privileged: true grants near-host access.`);
        if (/^network_mode:\s*["']?host/i.test(ln)) findings.push(`[HIGH] line ${n}: network_mode: host removes network isolation.`);
        if (/^pid:\s*["']?host/i.test(ln)) findings.push(`[HIGH] line ${n}: pid: host shares the host process namespace.`);
        if (/^ipc:\s*["']?host/i.test(ln)) findings.push(`[MED] line ${n}: ipc: host shares the host IPC namespace.`);
        if (/\/var\/run\/docker\.sock/.test(ln)) findings.push(`[HIGH] line ${n}: mounting docker.sock gives full control of the Docker daemon (host root).`);
        if (/^\s*-?\s*SYS_ADMIN/i.test(ln) || /cap_add[^#]*SYS_ADMIN/i.test(ln)) findings.push(`[HIGH] line ${n}: cap_add SYS_ADMIN is nearly root.`);
        if (/^image:\s*\S+:latest\s*$/i.test(ln)) findings.push(`[MED] line ${n}: image pinned to :latest — pin a specific version.`);
        if (/^image:\s*[^:\s#]+\s*$/i.test(ln) && !/@sha256:/.test(ln)) findings.push(`[LOW] line ${n}: image has no tag — defaults to :latest.`);
        if (/0\.0\.0\.0:\d+/.test(ln)) findings.push(`[LOW] line ${n}: port bound to 0.0.0.0 — exposed on all interfaces.`);
      });
      return findings.length ? `${findings.length} finding(s):\n` + findings.join("\n") : "No obvious risky compose settings found (heuristic).";
    } },

  { id: "cl-docker-run-explain", name: "docker run Flag Explainer", cat: "cloud", desc: "Explain the security-relevant flags of a docker run command and flag the dangerous ones.", tags: ["docker", "run", "explain", "security"],
    inputs: [{ k: "cmd", label: "docker run command", type: "textarea", rows: 4, placeholder: "docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock nginx" }],
    run(v) {
      const c = S(v.cmd).trim();
      if (!c) return "";
      const out = [];
      const has = (re) => re.test(c);
      if (has(/--privileged\b/)) out.push("[HIGH] --privileged: disables most isolation; container is effectively root on the host.");
      if (has(/\/var\/run\/docker\.sock/)) out.push("[HIGH] mounts docker.sock: full control of the Docker daemon = host root.");
      if (has(/--net(work)?[ =]host\b/)) out.push("[HIGH] --network host: no network namespace isolation.");
      if (has(/--pid[ =]host\b/)) out.push("[HIGH] --pid host: shares host process namespace.");
      if (has(/--cap-add[ =]?SYS_ADMIN/i)) out.push("[HIGH] --cap-add SYS_ADMIN: near-root capability.");
      const capAdds = c.match(/--cap-add[ =]\S+/gi) || [];
      capAdds.forEach((x) => { if (!/SYS_ADMIN/i.test(x)) out.push(`[MED] ${x}: capability added — confirm it is needed.`); });
      if (has(/-v\s+\/:\//) || has(/-v\s+\/:\/host/)) out.push("[HIGH] mounts the host root filesystem into the container.");
      if (has(/--user[ =]|-u\s+/)) out.push("[GOOD] runs as a specified user (not root).");
      if (has(/--read-only\b/)) out.push("[GOOD] --read-only root filesystem.");
      if (has(/--security-opt[ =]no-new-privileges/)) out.push("[GOOD] no-new-privileges set.");
      if (has(/--cap-drop[ =]?(all|ALL)/)) out.push("[GOOD] drops all capabilities.");
      return out.length ? out.join("\n") : "No security-relevant flags recognised in this command.";
    } },

  { id: "cl-docker-run-harden", name: "Hardened docker run Builder", cat: "cloud", desc: "Build a docker run command with hardening flags: non-root user, read-only fs, dropped capabilities and no-new-privileges.", tags: ["docker", "run", "harden", "builder"],
    inputs: [
      { k: "image", label: "Image", type: "text", placeholder: "nginx:1.27" },
      { k: "user", label: "User (uid:gid)", type: "text", value: "1000:1000" },
      { k: "readonly", label: "read-only root filesystem", type: "checkbox", value: true },
      { k: "tmpfs", label: "add writable tmpfs /tmp", type: "checkbox", value: true },
      { k: "ports", label: "Publish (host:container, optional)", type: "text", placeholder: "127.0.0.1:8080:80" },
      { k: "capadd", label: "Capabilities to add back (optional)", type: "text", placeholder: "NET_BIND_SERVICE" },
    ],
    run(v) {
      const img = S(v.image).trim();
      if (!img) return "";
      const parts = ["docker run --rm"];
      if (S(v.user).trim()) parts.push(`-u ${S(v.user).trim()}`);
      parts.push("--cap-drop ALL");
      S(v.capadd).split(/[\s,]+/).filter(Boolean).forEach((c) => parts.push(`--cap-add ${c}`));
      parts.push("--security-opt no-new-privileges");
      if (v.readonly) parts.push("--read-only");
      if (v.tmpfs) parts.push("--tmpfs /tmp:rw,noexec,nosuid");
      if (S(v.ports).trim()) parts.push(`-p ${S(v.ports).trim()}`);
      parts.push(img);
      return parts.join(" \\\n  ");
    } },

  { id: "cl-image-ref-parse", name: "Container Image Reference Parser", cat: "cloud", desc: "Parse a container image reference into registry, repository, tag and digest, applying Docker's default rules.", tags: ["docker", "oci", "image", "reference", "parse"],
    inputs: [{ k: "ref", label: "Image reference", type: "text", placeholder: "nginx:1.27 or ghcr.io/org/app@sha256:..." }],
    run(v) {
      const r = S(v.ref).trim();
      if (!r) return "";
      let rest = r, digest = "", tag = "";
      const at = rest.indexOf("@"); if (at >= 0) { digest = rest.slice(at + 1); rest = rest.slice(0, at); }
      const slash = rest.indexOf("/");
      const first = slash >= 0 ? rest.slice(0, slash) : "";
      const hasRegistry = first && (first.includes(".") || first.includes(":") || first === "localhost");
      let registry = "docker.io", path = rest;
      if (hasRegistry) { registry = first; path = rest.slice(slash + 1); }
      const colon = path.lastIndexOf(":");
      if (colon > path.lastIndexOf("/")) { tag = path.slice(colon + 1); path = path.slice(0, colon); }
      let repo = path;
      if (registry === "docker.io" && !repo.includes("/")) repo = "library/" + repo;
      if (!tag && !digest) tag = "latest";
      return lines([
        `registry    ${registry}${hasRegistry ? "" : " (default)"}`,
        `repository  ${repo}`,
        `tag         ${tag || "(none, digest-pinned)"}`,
        `digest      ${digest || "(none)"}`,
        `canonical   ${registry}/${repo}${tag ? ":" + tag : ""}${digest ? "@" + digest : ""}`,
      ]);
    } },

  { id: "cl-image-ref-build", name: "Container Image Reference Builder", cat: "cloud", desc: "Assemble a fully-qualified image reference from registry, repository, tag and optional digest.", tags: ["docker", "oci", "image", "reference", "build"],
    inputs: [
      { k: "registry", label: "Registry", type: "text", value: "docker.io" },
      { k: "repo", label: "Repository", type: "text", placeholder: "library/nginx" },
      { k: "tag", label: "Tag", type: "text", value: "latest" },
      { k: "digest", label: "Digest (optional)", type: "text", placeholder: "sha256:abc..." },
    ],
    run(v) {
      const repo = S(v.repo).trim();
      if (!repo) return "";
      const reg = S(v.registry).trim() || "docker.io";
      const tag = S(v.tag).trim(), digest = S(v.digest).trim();
      return `${reg}/${repo}${tag ? ":" + tag : ""}${digest ? "@" + digest : ""}`;
    } },

  { id: "cl-oci-ref-validate", name: "OCI Image Reference Validator", cat: "cloud", desc: "Validate the components of an image reference against the OCI distribution grammar (repository, tag, digest).", tags: ["oci", "image", "reference", "validate", "grammar"],
    inputs: [{ k: "ref", label: "Image reference", type: "text", placeholder: "registry.example.com/team/app:v1.0" }],
    run(v) {
      const r = S(v.ref).trim();
      if (!r) return "";
      let rest = r, digest = "", tag = "";
      const at = rest.indexOf("@"); if (at >= 0) { digest = rest.slice(at + 1); rest = rest.slice(0, at); }
      const slash = rest.indexOf("/");
      const first = slash >= 0 ? rest.slice(0, slash) : "";
      const hasReg = first && (first.includes(".") || first.includes(":") || first === "localhost");
      let path = hasReg ? rest.slice(slash + 1) : rest;
      const colon = path.lastIndexOf(":");
      if (colon > path.lastIndexOf("/")) { tag = path.slice(colon + 1); path = path.slice(0, colon); }
      const errs = [];
      const comp = /^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*$/;
      path.split("/").forEach((c) => { if (!comp.test(c)) errs.push(`repository component "${c}" is invalid (lowercase, separated by . _ __ or -).`); });
      if (tag && !/^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$/.test(tag)) errs.push(`tag "${tag}" is invalid (1-128 chars, start alnum/_).`);
      if (digest) { const dm = digest.match(/^([a-z0-9]+(?:[.+_-][a-z0-9]+)*):([a-zA-Z0-9=_-]+)$/); if (!dm) errs.push(`digest "${digest}" is not algo:hex form.`); else if (dm[1] === "sha256" && !/^[a-f0-9]{64}$/.test(dm[2])) errs.push("sha256 digest must be 64 hex chars."); else if (dm[1] === "sha512" && !/^[a-f0-9]{128}$/.test(dm[2])) errs.push("sha512 digest must be 128 hex chars."); }
      return errs.length ? `INVALID:\n- ${errs.join("\n- ")}` : `VALID per OCI grammar.\nrepository ${path}\ntag       ${tag || "(none)"}\ndigest    ${digest || "(none)"}`;
    } },

  { id: "cl-oci-labels-ref", name: "OCI Image Annotation Reference", cat: "cloud", desc: "Reference of the standard org.opencontainers.image.* annotation/label keys for images.", tags: ["oci", "image", "labels", "annotations", "reference"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "source, version..." }],
    run(v) {
      const L = [
        ["created", "Build date/time (RFC 3339)."], ["authors", "Contact details of the people/org."],
        ["url", "URL to find more information."], ["documentation", "URL to get documentation."],
        ["source", "URL to the source code (e.g. the git repo)."], ["version", "Version of the packaged software."],
        ["revision", "Source control revision (commit SHA)."], ["vendor", "Name of the distributing entity."],
        ["licenses", "SPDX license expression for the contents."], ["ref.name", "Author-defined name for the artifact."],
        ["title", "Human-readable title of the image."], ["description", "Human-readable description."],
        ["base.digest", "Digest of the image this was built from."], ["base.name", "Reference of the base image."],
      ];
      const q = S(v.q).toLowerCase().trim();
      const m = L.filter(([a, b]) => !q || a.includes(q) || b.toLowerCase().includes(q));
      return m.length ? m.map(([a, b]) => `org.opencontainers.image.${a}\n    ${b}`).join("\n") : "No matches.";
    } },

  { id: "cl-trivy-builder", name: "Trivy Scan Command Builder", cat: "cloud", desc: "Build a trivy command to scan a container image, filesystem or IaC config with chosen severities.", tags: ["trivy", "scanner", "image", "vulnerability", "builder"],
    inputs: [
      { k: "mode", label: "Scan", type: "select", opts: ["image", "filesystem", "config (IaC)", "repository"], value: "image" },
      { k: "target", label: "Target", type: "text", placeholder: "nginx:1.27 or ." },
      { k: "severity", label: "Severities", type: "text", value: "HIGH,CRITICAL" },
      { k: "ignoreUnfixed", label: "Ignore unfixed", type: "checkbox", value: false },
      { k: "exitCode", label: "Fail build on findings (exit 1)", type: "checkbox", value: false },
    ],
    run(v) {
      const target = S(v.target).trim();
      if (!target) return "";
      const sub = { "image": "image", "filesystem": "fs", "config (IaC)": "config", "repository": "repo" }[v.mode] || "image";
      const parts = [`trivy ${sub}`];
      if (S(v.severity).trim() && sub !== "config") parts.push(`--severity ${S(v.severity).trim().toUpperCase()}`);
      if (v.ignoreUnfixed) parts.push("--ignore-unfixed");
      if (v.exitCode) parts.push("--exit-code 1");
      parts.push(target);
      return parts.join(" ");
    } },

  { id: "cl-container-escape-ref", name: "Container Escape Vector Reference", cat: "cloud", desc: "Defensive reference of common container breakout/misconfiguration vectors and how to prevent each.", tags: ["container", "escape", "breakout", "reference", "defensive"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "socket, privileged..." }],
    run(v) {
      const E = [
        ["privileged container", "Near-total host access. Prevent: never run --privileged; use Restricted PSS."],
        ["docker.sock mount", "Mounting /var/run/docker.sock = control of the daemon = host root. Prevent: never mount it into untrusted containers."],
        ["hostPath / host root mount", "Mounting host paths (esp. /) lets a container read/modify host files. Prevent: avoid hostPath; use read-only, narrow mounts."],
        ["CAP_SYS_ADMIN", "Enables mount/namespace tricks used in many escapes. Prevent: drop ALL capabilities."],
        ["host PID namespace", "Can see/signal host processes and read their memory. Prevent: do not set hostPID/--pid=host."],
        ["host network namespace", "Reach loopback-bound host services (e.g. metadata). Prevent: avoid hostNetwork."],
        ["writable cgroup / release_agent", "Classic cgroup-v1 release_agent escape when privileged. Prevent: non-privileged, drop caps, cgroup v2."],
        ["exposed kubelet (10250)", "Unauthenticated kubelet allows exec into pods. Prevent: --anonymous-auth=false, --authorization-mode=Webhook."],
      ];
      const q = S(v.q).toLowerCase().trim();
      const m = E.filter(([a, b]) => !q || a.toLowerCase().includes(q) || b.toLowerCase().includes(q));
      return m.length ? m.map(([a, b]) => `${a}\n    ${b}`).join("\n") : "No matches.";
    } },

  // ======================= Terraform / HCL =======================
  { id: "cl-tf-address-parse", name: "Terraform Resource Address Parser", cat: "cloud", desc: "Parse a Terraform resource address into module path, type, name and index key.", tags: ["terraform", "address", "parse", "iac"],
    inputs: [{ k: "addr", label: "Resource address", type: "text", placeholder: 'module.net.aws_subnet.private["a"]' }],
    run(v) {
      const a = S(v.addr).trim();
      if (!a) return "";
      const modules = [];
      let rest = a;
      let m;
      while ((m = rest.match(/^module\.([A-Za-z0-9_-]+)\.(.*)$/))) { modules.push(m[1]); rest = m[2]; }
      const rm = rest.match(/^(data\.)?([A-Za-z0-9_]+)\.([A-Za-z0-9_-]+)(?:\[(.+)\])?$/);
      if (!rm) return { error: "Did not recognise a resource address (type.name[...])." };
      const idx = rm[4] ? rm[4].replace(/^["']|["']$/g, "") : "";
      return lines([
        `module path  ${modules.length ? modules.join(" > ") : "(root)"}`,
        `kind         ${rm[1] ? "data source" : "managed resource"}`,
        `type         ${rm[2]}`,
        `name         ${rm[3]}`,
        rm[4] ? `index key    ${idx}${/^\d+$/.test(rm[4]) ? " (count)" : " (for_each)"}` : null,
      ]);
    } },

  { id: "cl-hcl-var-extract", name: "HCL Reference Extractor", cat: "cloud", desc: "Extract all var., local., data. and module. references from Terraform HCL text.", tags: ["terraform", "hcl", "variables", "extract", "iac"],
    inputs: [{ k: "text", label: "HCL / Terraform code", type: "textarea", rows: 10, placeholder: 'resource "aws_instance" "x" {\n  ami = var.ami_id\n  subnet_id = module.net.subnet_id\n}' }],
    run(v) {
      const t = S(v.text);
      if (!t.trim()) return "";
      const grab = (re) => { const s = new Set(); let m; while ((m = re.exec(t))) s.add(m[1]); return [...s].sort(); };
      const vars = grab(/\bvar\.([A-Za-z0-9_]+)/g);
      const locals = grab(/\blocal\.([A-Za-z0-9_]+)/g);
      const data = grab(/\bdata\.([A-Za-z0-9_]+\.[A-Za-z0-9_]+)/g);
      const mods = grab(/\bmodule\.([A-Za-z0-9_]+\.[A-Za-z0-9_]+)/g);
      const sec = [];
      if (vars.length) sec.push("var:\n  " + vars.join("\n  "));
      if (locals.length) sec.push("local:\n  " + locals.join("\n  "));
      if (data.length) sec.push("data:\n  " + data.join("\n  "));
      if (mods.length) sec.push("module outputs:\n  " + mods.join("\n  "));
      return sec.length ? sec.join("\n\n") : "No var./local./data./module. references found.";
    } },

  // ======================= Metadata / IMDS =======================
  { id: "cl-imds-ssrf-explain", name: "Cloud Metadata SSRF Explainer", cat: "cloud", desc: "Explain the AWS, GCP and Azure instance metadata endpoints and how to defend them against SSRF (defensive reference).", tags: ["imds", "metadata", "ssrf", "169.254.169.254", "defensive"],
    inputs: [{ k: "cloud", label: "Cloud", type: "select", opts: ["All", "AWS", "GCP", "Azure"], value: "All" }],
    run(v) {
      const A = lines([
        "AWS IMDS — http://169.254.169.254/",
        "  IMDSv1: unauthenticated GET; a single SSRF can read credentials.",
        "  IMDSv2: requires a PUT token first (X-aws-ec2-metadata-token-ttl-seconds) then uses it as",
        "          X-aws-ec2-metadata-token; also enforces IP-TTL=1 so proxied SSRF is blocked.",
        "  Defend: enforce IMDSv2 (HttpTokens=required), set hop-limit 1, least-privilege instance roles.",
      ]);
      const G = lines([
        "GCP metadata — http://metadata.google.internal/ (169.254.169.254)",
        "  Requires header Metadata-Flavor: Google (blocks naive SSRF that cannot set headers).",
        "  Defend: never reflect unvalidated URLs; keep the required header check server-side.",
      ]);
      const Z = lines([
        "Azure IMDS — http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "  Requires header Metadata: true and rejects requests with an X-Forwarded-For header.",
        "  Defend: restrict egress; validate SSRF-prone fetchers; use managed identities carefully.",
      ]);
      const c = S(v.cloud);
      if (c === "AWS") return A; if (c === "GCP") return G; if (c === "Azure") return Z;
      return [A, G, Z].join("\n\n");
    } },

  { id: "cl-imds-paths-ref", name: "AWS IMDS Path Reference", cat: "cloud", desc: "Reference of notable AWS instance metadata paths (defensive: understand what a metadata SSRF could expose).", tags: ["imds", "aws", "metadata", "paths", "reference"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "credentials, user-data..." }],
    run(v) {
      const P = [
        ["/latest/meta-data/", "Index of metadata categories."],
        ["/latest/meta-data/iam/security-credentials/", "Lists the attached role; appending the role name returns TEMPORARY CREDENTIALS."],
        ["/latest/meta-data/iam/info", "IAM instance profile ARN."],
        ["/latest/user-data", "User-data script — may contain secrets/bootstrap config."],
        ["/latest/meta-data/instance-id", "Instance ID."],
        ["/latest/meta-data/local-ipv4", "Private IPv4 address."],
        ["/latest/meta-data/public-ipv4", "Public IPv4 address."],
        ["/latest/dynamic/instance-identity/document", "Signed instance identity document (account, region, instance type)."],
        ["/latest/api/token", "IMDSv2 token endpoint (PUT only)."],
      ];
      const q = S(v.q).toLowerCase().trim();
      const m = P.filter(([a, b]) => !q || a.toLowerCase().includes(q) || b.toLowerCase().includes(q));
      return (m.length ? m.map(([a, b]) => `${a}\n    ${b}`).join("\n") : "No matches.") + "\n\nThe iam/security-credentials path is the prize in most IMDS SSRF attacks — enforce IMDSv2.";
    } },

  { id: "cl-imdsv2-token", name: "AWS IMDSv2 Request Builder", cat: "cloud", desc: "Build the two-step IMDSv2 token-then-fetch curl commands for reading EC2 instance metadata.", tags: ["imds", "imdsv2", "aws", "curl", "builder"],
    inputs: [
      { k: "path", label: "Metadata path", type: "text", value: "/latest/meta-data/instance-id" },
      { k: "ttl", label: "Token TTL (seconds)", type: "text", value: "21600" },
    ],
    run(v) {
      const path = S(v.path).trim() || "/latest/meta-data/";
      const ttl = S(v.ttl).trim() || "21600";
      const p = path.startsWith("/") ? path : "/" + path;
      return lines([
        `# 1. Get a session token (valid ${ttl}s):`,
        `TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" \\`,
        `  -H "X-aws-ec2-metadata-token-ttl-seconds: ${ttl}")`,
        ``,
        `# 2. Use the token to read metadata:`,
        `curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \\`,
        `  "http://169.254.169.254${p}"`,
      ]);
    } },

  // ======================= Misc =======================
  { id: "cl-cloud-misconfig-checklist", name: "Cloud Misconfiguration Checklist", cat: "cloud", desc: "Searchable checklist of high-impact cloud misconfigurations and their consequences.", tags: ["cloud", "misconfig", "checklist", "audit", "reference"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "s3, iam, public..." }],
    run(v) {
      const C = [
        ["Public S3 bucket / object ACL or policy", "Data breach: anyone can list/download objects. Enable Block Public Access."],
        ["Security group 0.0.0.0/0 on 22/3389/db ports", "Brute force and direct compromise. Restrict source CIDRs; use a bastion/SSM."],
        ["IMDSv1 enabled on EC2", "A single SSRF steals instance-role credentials. Enforce IMDSv2 + hop-limit 1."],
        ["IAM wildcard (Action:* / Resource:*)", "Over-privileged principals; blast radius on compromise. Scope least-privilege."],
        ["Long-lived access keys / SA keys committed", "Credential theft and persistence. Use roles/short-lived tokens; rotate; scan repos."],
        ["No encryption at rest (S3/EBS/etcd/Secrets)", "Data readable if storage is exfiltrated. Enable default encryption/KMS."],
        ["No CloudTrail / audit logging", "No detection or forensics. Enable org-wide multi-region trails."],
        ["Public RDS / database endpoint", "Internet-exposed data store. Keep databases in private subnets."],
        ["Privileged / docker.sock containers", "Container escape to host root. Drop capabilities; never mount docker.sock."],
        ["Unauthenticated kubelet / etcd exposed", "Full cluster and Secret compromise. Enable auth; firewall ports 10250/2379."],
        ["allUsers / allAuthenticatedUsers IAM binding (GCP)", "Public access to resources. Remove public members."],
        ["SAS/presigned URLs with long expiry", "Leaked URL grants long-lived access. Keep validity short; scope narrowly."],
      ];
      const q = S(v.q).toLowerCase().trim();
      const m = C.filter(([a, b]) => !q || a.toLowerCase().includes(q) || b.toLowerCase().includes(q));
      return m.length ? m.map(([a, b], i) => `${i + 1}. ${a}\n    ${b}`).join("\n") : "No matches.";
    } },
];
