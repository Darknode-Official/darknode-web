// Regression tests for bugs found auditing the appsec (apispec, iacscan, k8saudit)
// and compliance (evidence, dataflow) engines against the Kubernetes RBAC / pod
// spec, the YAML merge-key rules and Dockerfile ADD semantics. One test per fix.

import { test, assert, group } from "../harness.mjs";
import * as K from "../../public/js/appsec/k8saudit-engine.js";
import * as A from "../../public/js/appsec/apispec-engine.js";
import * as I from "../../public/js/appsec/iacscan-engine.js";
import { toDay } from "../../public/js/compliance/evidence-engine.js";
import { parseRetention } from "../../public/js/compliance/dataflow-engine.js";

const k8s = (items) => K.analyze(K.parseInput([{ name: "dump.json", text: JSON.stringify({ apiVersion: "v1", kind: "List", items }) }]), { now: "2026-10-01" });
const iac = (name, text) => I.analyze(I.parseInput([{ name, text }]), {});
const ms = (fn) => { const t = Date.now(); fn(); return Date.now() - t; };

group("appsec / compliance audit fixes", () => {
  test("k8saudit: a privileged ephemeral (kubectl debug) container is flagged", () => {
    const pod = { apiVersion: "v1", kind: "Pod", metadata: { name: "web", namespace: "shop" }, spec: {
      containers: [{ name: "app", image: "example.com/app:1.0" }],
      ephemeralContainers: [{ name: "debugger", image: "example.com/busybox:1.36", securityContext: { privileged: true } }] } };
    const f = k8s([pod]).findings.filter((x) => x.check === "pod.privileged");
    assert.equal(f.length, 1);
    assert.ok(f[0].description.includes("debugger"));
  });

  test("k8saudit: \"pods/*\" is not an RBAC wildcard, \"*/exec\" is", () => {
    const perms = (resources) => K.dangerousPerms([{ apiGroups: [""], resources, verbs: ["create"] }]).map((p) => p.key);
    assert.ok(!perms(["pods/*"]).includes("pods-exec"));
    assert.ok(perms(["*/exec"]).includes("pods-exec"));
    assert.ok(perms(["pods/exec"]).includes("pods-exec"));
  });

  test("apispec: keys written before a YAML merge key override the merged ones", () => {
    const y = A.parseYaml("base: &b\n  security: []\n  x: 1\nop:\n  security:\n    - bearer: []\n  <<: *b\nitems:\n  - y: 0\n    <<: *b\n    x: 2\n");
    assert.deepEqual(y.op, { security: [{ bearer: [] }], x: 1 });
    assert.deepEqual(y.items, [{ security: [], x: 2, y: 0 }]);
  });

  test("iacscan: ADD of a remote tarball is flagged (only local archives auto-extract)", () => {
    const r = iac("Dockerfile", "FROM alpine:3.19\nADD https://example.com/tool.tgz /opt/\nADD rootfs.tar.gz /\nUSER 1000\n");
    const hits = r.findings.filter((f) => f.ruleId === "DKR-003").flatMap((f) => f.evidence.map((e) => e.detail));
    assert.ok(hits.some((d) => d.includes("https://example.com/tool.tgz")));
    assert.ok(!hits.some((d) => d.includes("rootfs.tar.gz")));
  });

  test("iacscan: curl pipe and TLS-off checks stay linear on a 140 KB RUN line", () => {
    const big = "FROM alpine:3.19\nRUN " + "curl x ".repeat(20000) + "&& curl -k https://example.com/i.sh | sh\nUSER 1000\n";
    let r;
    assert.ok(ms(() => { r = iac("Dockerfile", big); }) < 1500);
    const ids = r.findings.map((f) => f.ruleId);
    assert.ok(ids.includes("DKR-004") && ids.includes("DKR-014"));
    const clean = iac("Dockerfile", "FROM alpine:3.19\nRUN curl -o /tmp/x https://example.com/x && sh /tmp/x\nUSER 1000\n").findings.map((f) => f.ruleId);
    assert.ok(!clean.includes("DKR-004") && !clean.includes("DKR-014"));
  });

  test("evidence: toDay keeps the written calendar day in every time zone", () => {
    const prev = process.env.TZ;
    try {
      for (const tz of ["Asia/Tokyo", "America/Los_Angeles", "UTC"]) {
        process.env.TZ = tz;
        assert.equal(toDay("March 5, 2024"), "2024-03-05", tz);
        assert.equal(toDay("2024-03-05T05:00:00"), "2024-03-05", tz);
        assert.equal(toDay("2024-03-05T23:30:00-05:00"), "2024-03-05", tz);
      }
      assert.equal(toDay("2024-02-30T00:00:00Z"), null);
    } finally { if (prev === undefined) delete process.env.TZ; else process.env.TZ = prev; }
  });

  test("dataflow: parseRetention is linear on a long digit run and still reads periods", () => {
    assert.ok(ms(() => parseRetention("1".repeat(60000) + "x")) < 200);
    assert.equal(parseRetention("1.5 years").months, 18);
    assert.equal(parseRetention("kept 7 yrs after closure").months, 84);
    assert.equal(parseRetention("90 days").days, 90);
  });
});
